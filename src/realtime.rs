use crate::behavior::{ProcessTrust, RansomwareMonitor};
use crate::config::Settings;
use crate::detection::{
    open_candidate_file, opened_change_time, opened_file_identity, DetectionEngine,
    DetectionReport, DetectionVerdict,
};
use crate::history::{EventHistory, EventKind, SecurityEvent};
use crate::quarantine::{IsolationState, QuarantineRecord, QuarantineStore};
use crate::trust;
use crate::verdict_cache::{CacheVerdict, CachedVerdict, VerdictCache, VerdictCacheKey};
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

#[path = "connection_supervisor.rs"]
mod connection_supervisor;

use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, S_OK};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const BLACKSHARD_PROTOCOL_MAGIC: u32 = 0x3548_5342;
const BLACKSHARD_PROTOCOL_VERSION: u16 = 9;
const CONTROL_GET_HEALTH: u32 = 1;
const CONTROL_SET_READY_GENERATION: u32 = 2;
const CONTROL_SET_STOPPING: u32 = 3;
const OPERATION_OPEN: u32 = 1;
const OPERATION_EXECUTE_SECTION: u32 = 2;
const OPERATION_PROTECTED_WRITE: u32 = 3;
const OPERATION_PROTECTED_METADATA: u32 = 4;
const OPERATION_PROCESS_CREATE: u32 = 5;
pub(crate) const OPERATION_IMAGE_LOAD: u32 = 6;
const MAX_FILE_PATH_LENGTH: usize = 1024;
const MAX_COMMAND_LINE_LENGTH: usize = 2048;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[link(name = "FltLib")]
extern "system" {
    pub(crate) fn FilterConnectCommunicationPort(
        port_name: *const u16,
        options: u32,
        context: *const c_void,
        context_size: u16,
        security_attributes: *const c_void,
        port: *mut HANDLE,
    ) -> i32;

    pub(crate) fn FilterGetMessage(
        port: HANDLE,
        message_buffer: *mut c_void,
        message_buffer_size: u32,
        overlapped: *mut c_void,
    ) -> i32;

    pub(crate) fn FilterReplyMessage(
        port: HANDLE,
        reply_buffer: *mut c_void,
        reply_buffer_size: u32,
    ) -> i32;

    pub(crate) fn FilterSendMessage(
        port: HANDLE,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        bytes_returned: *mut u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DriverControlRequest {
    magic: u32,
    version: u16,
    size: u16,
    command: u32,
    generation: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DriverHealthReply {
    magic: u32,
    version: u16,
    size: u16,
    scan_requests: u64,
    blocks: u64,
    timeouts: u64,
    service_unavailable_bypasses: u64,
    object_resolution_bypasses: u64,
    oversize_path_bypasses: u64,
    irql_bypasses: u64,
    invalid_replies: u64,
    dirty_writes: u64,
    enforcement_bypasses: u64,
    content_race_blocks: u64,
    path_resolution_failures: u64,
    protocol_mismatches: u64,
    cache_allows: u64,
    boot_policy_allows: u64,
    required_enforcement_blocks: u64,
    queue_overloads: u64,
    ready_generation: u64,
    operational_phase: u32,
    features: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DriverOperationalPhase {
    #[default]
    EarlyBoot,
    Starting,
    Ready,
    Recovering,
    Stopping,
    SafeMode,
    Unknown(u32),
}

impl From<u32> for DriverOperationalPhase {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::EarlyBoot,
            1 => Self::Starting,
            2 => Self::Ready,
            3 => Self::Recovering,
            4 => Self::Stopping,
            5 => Self::SafeMode,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DriverHealthCounters {
    pub scan_requests: u64,
    pub blocks: u64,
    pub timeouts: u64,
    pub service_unavailable_bypasses: u64,
    pub object_resolution_bypasses: u64,
    pub oversize_path_bypasses: u64,
    pub irql_bypasses: u64,
    pub invalid_replies: u64,
    pub dirty_writes: u64,
    pub enforcement_bypasses: u64,
    pub content_race_blocks: u64,
    pub path_resolution_failures: u64,
    pub protocol_mismatches: u64,
    pub cache_allows: u64,
    pub boot_policy_allows: u64,
    pub required_enforcement_blocks: u64,
    pub queue_overloads: u64,
    pub ready_generation: u64,
    pub operational_phase: DriverOperationalPhase,
    pub features: u32,
}

/// Parts of the driver's protection that register separately at load and can be missing.
const DRIVER_FEATURES: &[(u32, &str)] = &[
    (0x1, "service process protection"),
    (0x2, "service registry protection"),
    (0x4, "process start notifications"),
    (0x8, "image load notifications"),
];

/// The protection parts a driver reporting `features` loaded without.
pub(crate) fn missing_driver_features(features: u32) -> Vec<&'static str> {
    DRIVER_FEATURES
        .iter()
        .filter(|(bit, _)| features & bit == 0)
        .map(|(_, name)| *name)
        .collect()
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct FilterMessageHeader {
    pub reply_length: u32,
    pub message_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct FilterReplyHeader {
    pub status: i32,
    pub message_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlackshardNotification {
    pub magic: u32,
    pub version: u16,
    pub size: u16,
    pub process_id: u32,
    pub desired_access: u32,
    pub operation: u32,
    pub path_length: u32,
    pub file_path: [u16; MAX_FILE_PATH_LENGTH],
    pub file_id: u64,
    pub content_generation: u64,
    pub process_start_key: u64,
    pub must_enforce: u32,
    pub reserved: u32,
    pub parent_process_id: u32,
    pub creating_process_id: u32,
    pub command_line_length: u32,
    pub reserved2: u32,
    pub command_line: [u16; MAX_COMMAND_LINE_LENGTH],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlackshardMessage {
    pub header: FilterMessageHeader,
    pub notification: BlackshardNotification,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverVerdict {
    Allow = 0,
    Block = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlackshardReplyMessage {
    pub header: FilterReplyHeader,
    pub magic: u32,
    pub version: u16,
    pub size: u16,
    pub verdict: DriverVerdict,
    pub risk_score: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionConnection {
    Connecting,
    Connected,
    Disconnected(String),
    Stopped,
}

#[derive(Debug, Clone)]
pub struct RealtimeDecision {
    pub process_id: u32,
    pub path: PathBuf,
    pub report: DetectionReport,

    pub block_reply_accepted: bool,
    pub quarantine: Option<QuarantineRecord>,
    pub action_error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RealtimeEvent {
    Connection(ProtectionConnection),
    Decision(Box<RealtimeDecision>),
    QueueSaturated { process_id: u32, path: PathBuf },
}

#[derive(Debug, Clone, Default)]
pub struct RealtimeCounters {
    pub scanned: u64,
    pub suspicious: u64,
    pub detected: u64,
    pub blocked_replies: u64,
    pub quarantined: u64,
    pub scan_errors: u64,
    pub bypassed_due_to_load: u64,
}

pub type SharedDetectionEngine = Arc<RwLock<Arc<DetectionEngine>>>;

pub fn new_shared_detection_engine(engine: DetectionEngine) -> SharedDetectionEngine {
    Arc::new(RwLock::new(Arc::new(engine)))
}

pub fn replace_detection_engine(shared: &SharedDetectionEngine, engine: DetectionEngine) {
    let mut active = shared
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *active = Arc::new(engine);
}

pub struct RealtimeProtection {
    stop: Arc<AtomicBool>,
    port: Arc<AtomicIsize>,
    worker: Option<JoinHandle<()>>,
    pub counters: Arc<Mutex<RealtimeCounters>>,
}

impl RealtimeProtection {
    pub fn start(
        engine: SharedDetectionEngine,
        quarantine: Arc<QuarantineStore>,
        history: Arc<EventHistory>,
        settings: Arc<RwLock<Settings>>,
        events: mpsc::SyncSender<RealtimeEvent>,
        verdict_cache: Arc<RwLock<VerdictCache>>,
        definition_generation: Arc<AtomicU64>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let port = Arc::new(AtomicIsize::new(0));
        let counters = Arc::new(Mutex::new(RealtimeCounters::default()));
        let worker_stop = Arc::clone(&stop);
        let worker_port = Arc::clone(&port);
        let worker_counters = Arc::clone(&counters);
        let worker = thread::Builder::new()
            .name("realtime-connection".to_owned())
            .spawn(move || {
                connection_supervisor::connection_loop(
                    engine,
                    quarantine,
                    history,
                    settings,
                    events,
                    worker_counters,
                    worker_stop,
                    worker_port,
                    verdict_cache,
                    definition_generation,
                )
            })
            .expect("failed to spawn the real-time connection thread");

        Self {
            stop,
            port,
            worker: Some(worker),
            counters,
        }
    }

    /// An inert instance for machines with no minifilter installed.
    ///
    /// Starting the supervisor there would retry a port that never opens, backing off to a
    /// 60 second cycle of failures for the life of the service. `driver_health` already reports an
    /// error while the port is zero, so callers need no other change.
    pub fn without_driver() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            port: Arc::new(AtomicIsize::new(0)),
            worker: None,
            counters: Arc::new(Mutex::new(RealtimeCounters::default())),
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Tell the driver this is on purpose; a disconnect it is not told about is treated as a
        // crash or a kill, and unjudged programs outside Windows and Program Files stay blocked.
        let told = match self.port.load(Ordering::Acquire) {
            0 => Ok(()),
            _ => self.send_control(CONTROL_SET_STOPPING, 0),
        };
        if let Err(error) = told {
            log::warn!("Could not tell the minifilter the service is stopping: {error}");
        }
        let handle = self.port.swap(0, Ordering::AcqRel);
        if handle != 0 {
            unsafe { CloseHandle(handle) };
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn driver_health(&self) -> Result<DriverHealthCounters, String> {
        query_driver_health(self.port.load(Ordering::Acquire))
    }

    pub fn set_ready_generation(&self, generation: u64) -> Result<(), String> {
        if generation == 0 {
            return Err("driver readiness generation zero is reserved".to_owned());
        }
        self.send_control(CONTROL_SET_READY_GENERATION, generation)
    }

    fn send_control(&self, command: u32, generation: u64) -> Result<(), String> {
        let port = self.port.load(Ordering::Acquire);
        if port == 0 {
            return Err("the kernel communication port is not connected".to_owned());
        }
        let request = DriverControlRequest {
            magic: BLACKSHARD_PROTOCOL_MAGIC,
            version: BLACKSHARD_PROTOCOL_VERSION,
            size: mem::size_of::<DriverControlRequest>() as u16,
            command,
            generation,
        };
        let mut returned = 0u32;
        let result = unsafe {
            FilterSendMessage(
                port,
                (&request as *const DriverControlRequest).cast(),
                mem::size_of::<DriverControlRequest>() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
            )
        };
        if result != S_OK {
            return Err(hresult_text(result));
        }
        if returned != 0 {
            return Err("the minifilter returned unexpected control data".to_owned());
        }
        Ok(())
    }
}

pub(crate) fn query_driver_health(port: HANDLE) -> Result<DriverHealthCounters, String> {
    if port == 0 {
        return Err("the kernel communication port is not connected".to_owned());
    }
    let request = DriverControlRequest {
        magic: BLACKSHARD_PROTOCOL_MAGIC,
        version: BLACKSHARD_PROTOCOL_VERSION,
        size: mem::size_of::<DriverControlRequest>() as u16,
        command: CONTROL_GET_HEALTH,
        generation: 0,
    };
    let mut reply = unsafe { mem::zeroed::<DriverHealthReply>() };
    let mut returned = 0u32;
    let result = unsafe {
        FilterSendMessage(
            port,
            (&request as *const DriverControlRequest).cast(),
            mem::size_of::<DriverControlRequest>() as u32,
            (&mut reply as *mut DriverHealthReply).cast(),
            mem::size_of::<DriverHealthReply>() as u32,
            &mut returned,
        )
    };
    if result != S_OK {
        return Err(hresult_text(result));
    }
    if returned as usize != mem::size_of::<DriverHealthReply>()
        || reply.magic != BLACKSHARD_PROTOCOL_MAGIC
        || reply.version != BLACKSHARD_PROTOCOL_VERSION
        || reply.size as usize != mem::size_of::<DriverHealthReply>()
    {
        return Err("the minifilter returned an invalid health record".to_owned());
    }
    Ok(DriverHealthCounters {
        scan_requests: reply.scan_requests,
        blocks: reply.blocks,
        timeouts: reply.timeouts,
        service_unavailable_bypasses: reply.service_unavailable_bypasses,
        object_resolution_bypasses: reply.object_resolution_bypasses,
        oversize_path_bypasses: reply.oversize_path_bypasses,
        irql_bypasses: reply.irql_bypasses,
        invalid_replies: reply.invalid_replies,
        dirty_writes: reply.dirty_writes,
        enforcement_bypasses: reply.enforcement_bypasses,
        content_race_blocks: reply.content_race_blocks,
        path_resolution_failures: reply.path_resolution_failures,
        protocol_mismatches: reply.protocol_mismatches,
        cache_allows: reply.cache_allows,
        boot_policy_allows: reply.boot_policy_allows,
        required_enforcement_blocks: reply.required_enforcement_blocks,
        queue_overloads: reply.queue_overloads,
        ready_generation: reply.ready_generation,
        operational_phase: reply.operational_phase.into(),
        features: reply.features,
    })
}

impl Drop for RealtimeProtection {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WorkItem {
    pub port: HANDLE,
    pub message: BlackshardMessage,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn realtime_worker(
    receiver: Arc<Mutex<mpsc::Receiver<WorkItem>>>,
    engine: SharedDetectionEngine,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Arc<RwLock<Settings>>,
    events: mpsc::SyncSender<RealtimeEvent>,
    counters: Arc<Mutex<RealtimeCounters>>,
    stop: Arc<AtomicBool>,
    ransomware_monitor: Arc<Mutex<RansomwareMonitor>>,
    process_trust_cache: Arc<Mutex<HashMap<(u32, u64), ProcessTrust>>>,
    verdict_cache: Arc<RwLock<VerdictCache>>,
    definition_generation: Arc<AtomicU64>,
) {
    loop {
        let item = {
            let receiver = match receiver.lock() {
                Ok(receiver) => receiver,
                Err(_) => return,
            };
            match receiver.recv() {
                Ok(item) => item,
                Err(_) => return,
            }
        };
        if stop.load(Ordering::Acquire) {
            let _ = reply(
                item.port,
                item.message.header.message_id,
                DriverVerdict::Allow,
                0,
            );
            continue;
        }
        let notification = item.message.notification;
        let kernel_path = notification_path(&notification);
        if matches!(
            notification.operation,
            OPERATION_PROTECTED_WRITE | OPERATION_PROTECTED_METADATA
        ) {
            handle_protected_modification(
                &item,
                &notification,
                &kernel_path,
                &settings,
                &history,
                &events,
                &counters,
                &ransomware_monitor,
                &process_trust_cache,
                &engine,
                &quarantine,
                &definition_generation,
            );
            continue;
        }
        let openable_path = device_path_to_openable_path(&kernel_path);
        if notification.operation == OPERATION_PROCESS_CREATE {
            record_process_start(&notification, &kernel_path, &ransomware_monitor);
        }
        let enabled = settings
            .read()
            .map(|value| value.real_time_active() && !value.is_excluded(&openable_path))
            .unwrap_or(false);
        if !enabled {
            let _ = reply(
                item.port,
                item.message.header.message_id,
                DriverVerdict::Allow,
                0,
            );
            continue;
        }

        // A browser's saved passwords and cookies: judged by who is opening them, not scanned.
        if notification.operation == OPERATION_OPEN
            && crate::command_rules::is_credential_store(&kernel_path.to_string_lossy())
        {
            judge_credential_store_open(
                &item,
                &notification,
                &kernel_path,
                &history,
                &counters,
                &engine,
                &quarantine,
                &definition_generation,
            );
            continue;
        }

        // How the program is being started can condemn it before its file is even scanned: a
        // signed Windows tool asked to delete shadow copies or to run script from the web.
        if notification.operation == OPERATION_PROCESS_CREATE {
            if let Some(hit) = judge_process_start(&notification, &kernel_path) {
                refuse_process_start(
                    &item,
                    &notification,
                    &kernel_path,
                    hit,
                    &history,
                    &counters,
                    &ransomware_monitor,
                    &engine,
                    &quarantine,
                    &definition_generation,
                );
                continue;
            }
        }

        // There is no cache lookup before the file is opened. The driver reports a file ID but no
        // volume, and NTFS file IDs repeat across volumes, so an ID-only hit could allow a file on
        // a removable drive unscanned on the strength of a clean verdict cached for C:. Opening
        // the file yields its full identity, and the exact-key lookup below still avoids a rescan.
        // Restoring a pre-open fast path needs the volume serial added to the driver notification.
        let scan = || {
            let candidate = open_candidate_file(&openable_path);
            let path = candidate
                .as_ref()
                .ok()
                .and_then(|file| opened_final_path(file).ok())
                .unwrap_or_else(|| kernel_path.clone());

            let active_engine = {
                let active = engine
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                Arc::clone(&active)
            };
            let report = match candidate {
                Ok(file) => match opened_file_identity(&file) {
                    Ok(identity) if identity.file_id == notification.file_id => {
                        let key = VerdictCacheKey {
                            volume_serial: identity.volume_serial_number as u64,
                            file_id: identity.file_id,
                            file_size: file.metadata().map(|m| m.len()).unwrap_or(0),
                            content_generation: notification.content_generation,
                            change_time: opened_change_time(&file).unwrap_or(0),
                        };
                        let current_gen = definition_generation.load(Ordering::Acquire);

                        let mut cached_result = None;
                        if let Ok(mut cache) = verdict_cache.write() {
                            cached_result = cache.get(&key, current_gen);
                        }

                        if let Some(cached) = cached_result {
                            log::debug!("Real-time cache hit for {:?}", key);
                            DetectionReport {
                                verdict: match cached.verdict {
                                    CacheVerdict::Clean => DetectionVerdict::Clean,
                                    CacheVerdict::Malicious => DetectionVerdict::Malicious,
                                    CacheVerdict::Suspicious => DetectionVerdict::Suspicious,
                                    CacheVerdict::ScanError => DetectionVerdict::Error,
                                },
                                risk_score: cached.risk_score as u8,
                                confidence: cached.confidence,
                                threat_name: cached.threat_name.clone(),
                                sha256: cached.sha256.clone(),
                                file_size: cached.file_size,
                                bytes_scanned: cached.bytes_scanned,
                                truncated: cached.truncated,
                                analysis_completeness: cached.analysis_completeness,
                                static_report: None,
                                rule_matches: Vec::new(),
                                similarity_matches: Vec::new(),
                                container_inspection: None,
                                amsi_report: None,
                                amsi_error: None,
                                elapsed: std::time::Duration::ZERO,
                                from_cache: true,
                                error: None,
                                automatic_quarantine_eligible: cached.automatic_quarantine_eligible,
                                execution_block_eligible: cached.execution_block_eligible,
                            }
                        } else {
                            log::debug!("Real-time cache miss for {:?}", key);
                            let scan_result = active_engine.scan_open_file(&file);

                            if let Ok(mut cache) = verdict_cache.write() {
                                cache.insert(
                                    key,
                                    CachedVerdict {
                                        verdict: match scan_result.verdict {
                                            DetectionVerdict::Clean => CacheVerdict::Clean,
                                            DetectionVerdict::Malicious => CacheVerdict::Malicious,
                                            DetectionVerdict::Suspicious => {
                                                CacheVerdict::Suspicious
                                            }
                                            DetectionVerdict::Error => CacheVerdict::ScanError,
                                        },
                                        risk_score: scan_result.risk_score as u32,
                                        confidence: scan_result.confidence,
                                        threat_name: scan_result.threat_name.clone(),
                                        sha256: scan_result.sha256.clone(),
                                        file_size: scan_result.file_size,
                                        bytes_scanned: scan_result.bytes_scanned,
                                        truncated: scan_result.truncated,
                                        definition_generation: current_gen,
                                        scanned_at: chrono::Utc::now(),
                                        analysis_completeness: scan_result.analysis_completeness,
                                        automatic_quarantine_eligible: scan_result
                                            .automatic_quarantine_eligible,
                                        execution_block_eligible: scan_result
                                            .execution_block_eligible,
                                    },
                                );
                            }
                            scan_result
                        }
                    }
                    // A process start the driver had no file identity for: scanned, uncached.
                    Ok(_) if notification.file_id == 0 => active_engine.scan_open_file(&file),
                    Ok(identity) => DetectionReport::error(
                        format!(
                            "kernel/user file identity mismatch (expected {:016x}, opened {:016x})",
                            notification.file_id, identity.file_id
                        ),
                        Duration::ZERO,
                    ),
                    Err(error) => DetectionReport::error(
                        format!("could not verify the opened file identity: {error}"),
                        Duration::ZERO,
                    ),
                },
                Err(error) => DetectionReport::error(
                    format!("could not open the exact candidate for analysis: {error}"),
                    Duration::ZERO,
                ),
            };
            (report, path)
        };
        let (mut report, mut path) = scan();
        // An execution that could not be judged: the file changed underneath the scan, was swapped
        // for another, or could not be opened. Those are the tricks a launcher plays to get an
        // image past the scan, so it is tried once more and then refused unless it is signed.
        if notification.operation == OPERATION_EXECUTE_SECTION
            && report.verdict == DetectionVerdict::Error
        {
            (report, path) = scan();
            if report.verdict == DetectionVerdict::Error
                && !trust::verify_file_cached(&path).is_trusted()
            {
                log::warn!(
                    "Blocked execution of {path:?}: it could not be scanned ({})",
                    report.error.as_deref().unwrap_or("unknown error")
                );
                report.execution_block_eligible = true;
            }
        }
        if matches!(
            notification.operation,
            OPERATION_EXECUTE_SECTION | OPERATION_PROCESS_CREATE
        ) && !report.execution_block_eligible
        {
            if let Some(reason) = execution_reputation(&path, notification.process_id, &report) {
                log::warn!("Blocked execution of {path:?}: {reason}");
                report.execution_block_eligible = true;
                if report.verdict == DetectionVerdict::Clean {
                    report.verdict = DetectionVerdict::Suspicious;
                }
                report.threat_name.get_or_insert_with(|| reason.to_owned());
            }
        }
        let driver_verdict = execution_driver_verdict(&report);
        let reply_accepted = reply(
            item.port,
            item.message.header.message_id,
            driver_verdict,
            report.risk_score as u32,
        );

        // No process is terminated here. For an open, the requester only read the file and may
        // well be innocent: Explorer drawing an icon, the indexer, a browser checking a download.
        // For an execution, denying the image section already stops the program, and the process
        // that requested the section is the one launching it, not the program itself.

        let mut quarantine_record = None;
        let mut action_error = None;
        if report.should_quarantine() {
            let threat_name = report.threat_name.as_deref().unwrap_or("Known.Malware");
            let should_quarantine = settings
                .read()
                .map(|value| value.automatic_quarantine)
                .unwrap_or(true);
            if should_quarantine {
                let quarantine_result = match report.sha256.as_deref() {
                    Some(hash) => quarantine.quarantine_verified(
                        &openable_path,
                        threat_name,
                        report.risk_score,
                        hash,
                        report.file_size,
                        Some(notification.file_id).filter(|id| *id != 0),
                    ),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the complete file was not hashed; automatic quarantine was withheld",
                    )),
                };
                match quarantine_result {
                    Ok(record) => {
                        let isolated = record.state == IsolationState::Isolated;
                        if isolated {
                            if let Ok(mut value) = counters.lock() {
                                value.quarantined += 1;
                            }
                        } else {
                            action_error = Some(
                                "the source remained after creating a neutralized copy".to_owned(),
                            );
                        }
                        let mut event = SecurityEvent::new(
                            if isolated {
                                EventKind::Quarantined
                            } else {
                                EventKind::QuarantineFailed
                            },
                            if isolated {
                                "Real-time threat moved to quarantine"
                            } else {
                                "Real-time threat blocked; original could not be removed"
                            },
                        );
                        event.path = Some(path.clone());
                        event.threat_name = Some(threat_name.to_owned());
                        event.risk_score = Some(report.risk_score);
                        event.details = record.cleanup_summary();
                        let _ = history.append(&event);
                        quarantine_record = Some(record);
                    }
                    Err(error) => {
                        action_error = Some(error.to_string());
                        let mut event = SecurityEvent::new(
                            EventKind::QuarantineFailed,
                            "Real-time threat blocked; quarantine failed",
                        );
                        event.path = Some(path.clone());
                        event.threat_name = Some(threat_name.to_owned());
                        event.risk_score = Some(report.risk_score);
                        event.details = action_error.clone();
                        let _ = history.append(&event);
                    }
                }
            }
        }

        // "Accepted" alone only means the driver received the reply. A suspicious verdict is an
        // allow, and recording it as an accepted block raised "threat blocked" toasts for
        // programs that ran.
        let blocked = driver_verdict == DriverVerdict::Block && reply_accepted;
        if let Ok(mut value) = counters.lock() {
            value.scanned += 1;
            match report.verdict {
                DetectionVerdict::Clean => {}
                DetectionVerdict::Suspicious => value.suspicious += 1,
                DetectionVerdict::Malicious => value.detected += 1,
                DetectionVerdict::Error => value.scan_errors += 1,
            }
            if blocked {
                value.blocked_replies += 1;
            }
        }

        if report.verdict != DetectionVerdict::Clean {
            let mut event = SecurityEvent::new(
                EventKind::Detection,
                match report.verdict {
                    DetectionVerdict::Malicious => "Real-time malicious file detected",
                    DetectionVerdict::Suspicious => "Real-time suspicious file observed",
                    DetectionVerdict::Error => "Real-time scan failed",
                    DetectionVerdict::Clean => unreachable!(),
                },
            );
            event.path = Some(path.clone());
            event.threat_name = report.threat_name.clone();
            event.risk_score = Some(report.risk_score);
            event.details = Some(format!(
                "block_reply_accepted={blocked}; pid={}{}",
                item.message.notification.process_id,
                if notification.operation == OPERATION_PROCESS_CREATE {
                    format!(
                        "; command_line={}",
                        notification_command_line(&notification)
                    )
                } else {
                    String::new()
                }
            ));
            let _ = history.append(&event);
        }

        if report.verdict != DetectionVerdict::Clean {
            let _ = events.try_send(RealtimeEvent::Decision(Box::new(RealtimeDecision {
                process_id: notification.process_id,
                path,
                report,
                block_reply_accepted: blocked,
                quarantine: quarantine_record,
                action_error,
            })));
        }
    }
}

fn execution_driver_verdict(report: &DetectionReport) -> DriverVerdict {
    if report.should_block() {
        DriverVerdict::Block
    } else {
        DriverVerdict::Allow
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_protected_modification(
    item: &WorkItem,
    notification: &BlackshardNotification,
    path: &Path,
    settings: &Arc<RwLock<Settings>>,
    history: &Arc<EventHistory>,
    events: &mpsc::SyncSender<RealtimeEvent>,
    counters: &Arc<Mutex<RealtimeCounters>>,
    monitor: &Arc<Mutex<RansomwareMonitor>>,
    trust_cache: &Arc<Mutex<HashMap<(u32, u64), ProcessTrust>>>,
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    definition_generation: &AtomicU64,
) {
    let observed_at = std::time::SystemTime::now();
    let (enabled, paused, block_mode, keep_copies) = settings
        .read()
        .map(|settings| {
            (
                settings.real_time_protection
                    && settings.ransomware_protection
                    && !settings.is_excluded(path),
                settings.is_paused(),
                settings.ransomware_block_mode,
                settings.rollback_documents,
            )
        })
        .unwrap_or((false, false, false, false));
    // Paused, nothing is judged or blocked, but documents are still copied: the turbo hunt that
    // ends the pause puts back what the programs it convicts changed meanwhile.
    if !enabled || (paused && !keep_copies) {
        let _ = reply(
            item.port,
            item.message.header.message_id,
            DriverVerdict::Allow,
            0,
        );
        return;
    }
    let process_trust = cached_process_trust(
        trust_cache,
        notification.process_id,
        notification.process_start_key,
    );
    let action = match notification.operation {
        OPERATION_PROTECTED_WRITE => Some(crate::behavior::FileAction::Write {
            entropy: match notification.desired_access {
                1 => crate::behavior::EntropyObservation::Low,
                2 => crate::behavior::EntropyObservation::Normal,
                3 => crate::behavior::EntropyObservation::High,
                _ => crate::behavior::EntropyObservation::NotMeasured,
            },
        }),
        OPERATION_PROTECTED_METADATA => Some(crate::behavior::FileAction::Rename),
        _ => None,
    };
    // Save the original before the driver lets the operation through; the notification arrives
    // ahead of the write, rename or delete. Signed programs are skipped: they edit documents all
    // day, and a hijacked one is rarer than the cost of copying everything they touch.
    if keep_copies
        && process_trust != ProcessTrust::Trusted
        && action.is_some()
        && notification.process_id != 0
        && notification.process_start_key != 0
    {
        // The driver reports `\Device\HarddiskVolumeN\...`, which Win32 file calls cannot open,
        // and restore checks folders by their drive-letter path; the vault keeps that form.
        if let (Some(vault), Some(document)) =
            (crate::rollback::global(), device_path_to_dos_path(path))
        {
            vault.preserve(
                (notification.process_id, notification.process_start_key),
                &document,
            );
        }
    }
    if paused {
        let _ = reply(
            item.port,
            item.message.header.message_id,
            DriverVerdict::Allow,
            0,
        );
        return;
    }
    let mut decision = monitor
        .lock()
        .map(|mut monitor| {
            monitor.observe(
                notification.process_id,
                notification.process_start_key,
                path,
                process_trust,
                block_mode,
                action,
            )
        })
        .unwrap_or_default();
    // A decoy no person opens: the first program not signed by a trusted publisher to change it
    // is ransomware, however slowly it goes.
    if action.is_some()
        && process_trust != ProcessTrust::Trusted
        && device_path_to_dos_path(path).is_some_and(|document| crate::canary::is_decoy(&document))
    {
        log::warn!(
            "PID {} changed a ransomware decoy: {path:?}",
            notification.process_id
        );
        decision.alert = true;
        decision.block = block_mode;
        decision.distinct_files = decision.distinct_files.max(1);
    }
    let verdict = if decision.block {
        DriverVerdict::Block
    } else {
        DriverVerdict::Allow
    };
    let accepted = reply(
        item.port,
        item.message.header.message_id,
        verdict,
        if decision.alert || decision.block {
            95
        } else {
            0
        },
    );
    if decision.block && accepted {
        if let Ok(mut counters) = counters.lock() {
            counters.blocked_replies += 1;
        }
        let terminated = (notification.process_id != 0)
            .then(|| terminate_ransomware_process(notification.process_id, observed_at))
            .flatten();
        undo_ransomware_damage(
            (notification.process_id, notification.process_start_key),
            history,
        );
        // Only an unsigned writer is learned. A signed program doing this is far more likely
        // hijacked than malicious itself, and a shard for powershell.exe would break the machine.
        if let (Some(image), ProcessTrust::Untrusted) = (terminated, process_trust) {
            if behaviour_removal_allowed(&image, &system_root(), &program_files_folders()) {
                learn_and_quarantine(
                    &image,
                    "Shard.Behavior.Ransomware",
                    engine,
                    quarantine,
                    history,
                    definition_generation,
                );
            } else {
                log::warn!(
                    "Stopped {image:?} for ransomware-like writes; it is installed software, so it was not removed"
                );
            }
        }
    }
    if !decision.alert {
        return;
    }

    let report = DetectionReport::ransomware_behavior(
        decision.distinct_files,
        decision.block,
        Duration::ZERO,
    );
    let mut event = SecurityEvent::new(
        EventKind::Detection,
        if decision.block {
            "Ransomware-like mass modification blocked"
        } else {
            "Ransomware-like mass modification observed (audit mode)"
        },
    );
    event.path = Some(path.to_path_buf());
    event.threat_name = report.threat_name.clone();
    event.risk_score = Some(report.risk_score);
    event.details = Some(format!(
        "pid={}; process_start_key={:016x}; operation={}; distinct_protected_files={}; block_mode={block_mode}; block_reply_accepted={accepted}",
        notification.process_id,
        notification.process_start_key,
        if notification.operation == OPERATION_PROTECTED_WRITE {
            "write"
        } else {
            "rename-or-delete"
        },
        decision.distinct_files
    ));
    if let Some(command_line) = monitor.lock().ok().and_then(|monitor| {
        monitor
            .process_start(notification.process_id, notification.process_start_key)
            .map(|start| start.command_line.clone())
    }) {
        if let Some(details) = event.details.as_mut() {
            details.push_str(&format!("; command_line={command_line}"));
        }
    }
    let _ = history.append(&event);
    let _ = events.try_send(RealtimeEvent::Decision(Box::new(RealtimeDecision {
        process_id: notification.process_id,
        path: path.to_path_buf(),
        report,
        block_reply_accepted: decision.block && accepted,
        quarantine: None,
        action_error: None,
    })));
}

/// Puts back the documents a convicted program changed, from the copies saved before it touched
/// them. The program has just been terminated, so nothing is writing to them.
fn undo_ransomware_damage(process: crate::rollback::ProcessKey, history: &EventHistory) {
    let Some(vault) = crate::rollback::global() else {
        return;
    };
    let summary = vault.restore(process, |folder| {
        crate::quarantine::pin_restore_directory(folder)
    });
    if summary.restored + summary.failed == 0 {
        return;
    }
    let mut event = SecurityEvent::new(
        if summary.failed == 0 {
            EventKind::Restored
        } else {
            EventKind::Error
        },
        if summary.failed == 0 {
            "Ransomware damage undone"
        } else {
            "Ransomware damage only partly undone"
        },
    );
    event.details = Some(format!(
        "pid={}; files_restored={}; files_unchanged={}; files_not_restored={}",
        process.0, summary.restored, summary.unchanged, summary.failed
    ));
    let _ = history.append(&event);
}

/// Turns a behavioural conviction into a shard, so the program is blocked on sight from now on,
/// and moves the program itself to quarantine.
fn learn_and_quarantine(
    image: &Path,
    threat_name: &str,
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    history: &EventHistory,
    definition_generation: &AtomicU64,
) {
    let active = Arc::clone(
        &engine
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    let report = active.scan_path(image);
    let Some(sha256) = report.sha256.as_deref() else {
        log::warn!("Could not hash {image:?} to learn it: {:?}", report.error);
        return;
    };
    match crate::shards::learn(sha256, threat_name) {
        // Cached clean verdicts for this file are stale now.
        Ok(_) => {
            definition_generation.fetch_add(1, Ordering::AcqRel);
        }
        Err(error) => log::warn!("Could not learn a shard for {image:?}: {error}"),
    }
    let (kind, summary, details) = match quarantine.quarantine_verified(
        image,
        threat_name,
        100,
        sha256,
        report.file_size,
        None,
    ) {
        Ok(record) if record.state == IsolationState::Isolated => (
            EventKind::Quarantined,
            "Program stopped for what it did, learned and moved to quarantine",
            record.cleanup_summary(),
        ),
        Ok(_) => (
            EventKind::QuarantineFailed,
            "Program stopped for what it did and learned; its file could not be removed",
            None,
        ),
        Err(error) => (
            EventKind::QuarantineFailed,
            "Program stopped for what it did and learned; quarantine failed",
            Some(error.to_string()),
        ),
    };
    let mut event = SecurityEvent::new(kind, summary);
    event.path = Some(image.to_path_buf());
    event.threat_name = Some(threat_name.to_owned());
    event.risk_score = Some(100);
    event.details = details;
    let _ = history.append(&event);
}

fn cached_process_trust(
    cache: &Mutex<HashMap<(u32, u64), ProcessTrust>>,
    process_id: u32,
    process_start_key: u64,
) -> ProcessTrust {
    let key = (process_id, process_start_key);
    if let Ok(mut cache) = cache.lock() {
        if let Some(trust) = cache.get(&key) {
            return *trust;
        }

        if cache.len() >= 256 {
            // Entries are never evicted one by one, and refusing to resolve once full left every
            // later process Unknown for the life of the service.
            cache.clear();
        }
    }
    let resolved = process_image_path(process_id)
        .map(|path| match trust::verify_file(&path) {
            trust::AuthenticodeStatus::Trusted { .. } => ProcessTrust::Trusted,
            trust::AuthenticodeStatus::Unsigned | trust::AuthenticodeStatus::Untrusted(_) => {
                ProcessTrust::Untrusted
            }
            trust::AuthenticodeStatus::Error(_) => ProcessTrust::Unknown,
        })
        .unwrap_or(ProcessTrust::Unknown);
    if let Ok(mut cache) = cache.lock() {
        cache.insert(key, resolved);
    }
    resolved
}

pub(crate) fn process_image_path(process_id: u32) -> Option<PathBuf> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process == 0 {
        return None;
    }
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    let succeeded =
        unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } != 0;
    unsafe { CloseHandle(process) };
    if !succeeded || length == 0 || length as usize > buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

pub(crate) fn reply(
    port: HANDLE,
    message_id: u64,
    verdict: DriverVerdict,
    risk_score: u32,
) -> bool {
    let mut reply = BlackshardReplyMessage {
        header: FilterReplyHeader {
            status: 0,
            message_id,
        },
        magic: BLACKSHARD_PROTOCOL_MAGIC,
        version: BLACKSHARD_PROTOCOL_VERSION,
        size: (mem::size_of::<BlackshardReplyMessage>() - mem::size_of::<FilterReplyHeader>())
            as u16,
        verdict,
        risk_score,
    };
    unsafe {
        FilterReplyMessage(
            port,
            &mut reply as *mut _ as *mut c_void,
            mem::size_of::<BlackshardReplyMessage>() as u32,
        ) == S_OK
    }
}

/// Execution rules a file scan alone cannot apply, because they depend on where the file came
/// from or who is loading it: an unsigned DLL named like a Windows one beside the signed program
/// loading it (side-loading), and an unsigned file the engine finds suspicious that was
/// downloaded from the internet.
fn execution_reputation(
    path: &Path,
    requester: u32,
    report: &DetectionReport,
) -> Option<&'static str> {
    let text = path.to_string_lossy();
    let lower = text.to_ascii_lowercase();
    if lower.ends_with(".dll") || lower.ends_with(".ocx") || lower.ends_with(".cpl") {
        if let Some(host) = process_image_path(requester) {
            if crate::command_rules::looks_side_loaded(&text, &host.to_string_lossy())
                && trust::verify_file_cached(&host).is_trusted()
                && !trust::verify_file_cached(path).is_trusted()
            {
                return Some("Behavior.Win.DllSideLoading");
            }
        }
    }
    if hidden_on_removable_drive(path) && !trust::verify_file_cached(path).is_trusted() {
        return Some("Behavior.Win.RemovableDriveWorm");
    }
    if report.verdict == DetectionVerdict::Suspicious {
        let downloaded = std::fs::read_to_string(format!("{text}:Zone.Identifier"))
            .ok()
            .and_then(|zone| crate::command_rules::download_zone(&zone))
            .is_some_and(|zone| zone >= 3);
        if downloaded && !trust::verify_file_cached(path).is_trusted() {
            return Some("Reputation.Win.SuspiciousDownload");
        }
    }
    None
}

/// Whether a file is hidden and on a removable drive. USB worms (XWorm, Raspberry Robin's
/// droppers) hide their own copy on the stick and leave a shortcut that runs it; a person's own
/// portable programs are not hidden.
fn hidden_on_removable_drive(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOVABLE: u32 = 2;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    let text = path.to_string_lossy();
    let text = text.trim_start_matches(r"\\?\");
    let bytes = text.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let root: Vec<u16> = format!("{}:\\", bytes[0] as char)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let removable = unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_REMOVABLE;
    removable
        && std::fs::metadata(path)
            .is_ok_and(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
}

/// Lets a browser, or a program signed by a trusted publisher, open a browser's credential store,
/// and refuses anything else: an infostealer copying `Login Data` or `Cookies`. The refused program
/// is stopped and, where a user or download could have put it, learned and quarantined.
#[allow(clippy::too_many_arguments)]
fn judge_credential_store_open(
    item: &WorkItem,
    notification: &BlackshardNotification,
    kernel_path: &Path,
    history: &EventHistory,
    counters: &Mutex<RealtimeCounters>,
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    definition_generation: &AtomicU64,
) {
    let requester = process_image_path(notification.process_id);
    let allowed = requester.as_ref().is_some_and(|image| {
        crate::command_rules::owns_credential_store(&image.to_string_lossy())
            || trust::verify_file_cached(image).is_trusted()
    });
    let verdict = if allowed {
        DriverVerdict::Allow
    } else {
        DriverVerdict::Block
    };
    let accepted = reply(item.port, item.message.header.message_id, verdict, 0);
    if allowed {
        return;
    }
    let hit = crate::command_rules::CREDENTIAL_THEFT;
    if let Ok(mut value) = counters.lock() {
        value.detected += 1;
        if accepted {
            value.blocked_replies += 1;
        }
    }
    let store = device_path_to_dos_path(kernel_path).unwrap_or_else(|| kernel_path.to_path_buf());
    log::warn!(
        "Refused PID {} ({requester:?}) access to {store:?}",
        notification.process_id
    );
    let mut event = SecurityEvent::new(EventKind::Detection, "Browser credential theft refused");
    event.path = Some(store);
    event.threat_name = Some(hit.name.to_owned());
    event.risk_score = Some(100);
    event.details = Some(format!(
        "block_reply_accepted={accepted}; reason={}; pid={}; program={}",
        hit.reason,
        notification.process_id,
        requester
            .as_ref()
            .map(|image| image.display().to_string())
            .unwrap_or_default()
    ));
    let _ = history.append(&event);
    convict_process(
        notification.process_id,
        hit.name,
        history,
        engine,
        quarantine,
        definition_generation,
    );
}

/// The command-line rules' verdict on a process start.
fn judge_process_start(
    notification: &BlackshardNotification,
    kernel_image: &Path,
) -> Option<crate::command_rules::RuleHit> {
    let image = device_path_to_dos_path(kernel_image).unwrap_or_else(|| kernel_image.to_path_buf());
    let image = image.to_string_lossy();
    let command_line = notification_command_line(notification);
    // The creating process, not the "parent": a parent can be named freely at creation time,
    // which malware uses to make its children look like Explorer's.
    let creator = process_image_path(notification.creating_process_id);
    let creator = creator.as_ref().map(|path| path.to_string_lossy());
    crate::command_rules::judge_launch(&crate::command_rules::Launch {
        image: &image,
        command_line: &command_line,
        creator_image: creator.as_deref(),
    })
}

/// Refuses a process start a rule condemned, records it, and, when the rule says the program
/// asking for it is the threat, stops and removes that program.
#[allow(clippy::too_many_arguments)]
fn refuse_process_start(
    item: &WorkItem,
    notification: &BlackshardNotification,
    kernel_image: &Path,
    hit: crate::command_rules::RuleHit,
    history: &EventHistory,
    counters: &Mutex<RealtimeCounters>,
    monitor: &Mutex<RansomwareMonitor>,
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    definition_generation: &AtomicU64,
) {
    let accepted = reply(
        item.port,
        item.message.header.message_id,
        DriverVerdict::Block,
        100,
    );
    if let Ok(mut value) = counters.lock() {
        value.scanned += 1;
        value.detected += 1;
        if accepted {
            value.blocked_replies += 1;
        }
    }
    let command_line = notification_command_line(notification);
    log::warn!(
        "Refused {kernel_image:?} ({}): {}; {command_line}",
        hit.name,
        hit.reason
    );
    let mut event = SecurityEvent::new(EventKind::Detection, "Program start refused");
    event.path =
        Some(device_path_to_dos_path(kernel_image).unwrap_or_else(|| kernel_image.to_path_buf()));
    event.threat_name = Some(hit.name.to_owned());
    event.risk_score = Some(100);
    event.details = Some(format!(
        "block_reply_accepted={accepted}; reason={}; pid={}; creator={}; command_line={}",
        hit.reason,
        notification.process_id,
        notification.creating_process_id,
        command_line.chars().take(1024).collect::<String>()
    ));
    let _ = history.append(&event);

    if hit.convict_launcher {
        if let Some(culprit) = launcher_behind(notification.creating_process_id, monitor) {
            convict_process(
                culprit,
                hit.name,
                history,
                engine,
                quarantine,
                definition_generation,
            );
        }
    }
}

/// The program really behind a command: the creator itself, or, when the creator is a shell or
/// script host that only ran the command for someone, whoever started that. Ransomware usually
/// runs `cmd /c vssadmin delete shadows`, so the shell is skipped to reach it.
fn launcher_behind(creating_process_id: u32, monitor: &Mutex<RansomwareMonitor>) -> Option<u32> {
    const RELAYS: &[&str] = &[
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "conhost.exe",
        "rundll32.exe",
        "wmiprvse.exe",
    ];
    let mut process_id = creating_process_id;
    // A few hops at most: a chain longer than that is not a relay.
    for _ in 0..4 {
        let image = process_image_path(process_id)?;
        let name = image
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !RELAYS.contains(&name.as_str()) {
            return Some(process_id);
        }
        let creator = monitor
            .lock()
            .ok()?
            .latest_start(process_id)
            .map(|start| start.creating_process_id)?;
        if creator == 0 || creator == process_id {
            return None;
        }
        process_id = creator;
    }
    None
}

/// Stops a program a rule found to be the threat, puts back the documents it changed, and, if it
/// lives where a user or a download can put a program, learns and quarantines it. A signed
/// program is left running: refusing its command was enough, and it is far more likely abused
/// than malicious.
fn convict_process(
    process_id: u32,
    threat_name: &str,
    history: &EventHistory,
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    definition_generation: &AtomicU64,
) {
    let Some(target) = open_target(process_id, std::time::SystemTime::now(), None) else {
        return;
    };
    if trust::verify_file_cached(&target.image).is_trusted() {
        log::warn!(
            "{:?} asked for a refused command but is signed; it was left running",
            target.image
        );
        return;
    }
    for (process_id, created_at, image) in terminate_all(vec![target]) {
        undo_documents_changed_by(process_id, created_at);
        if behaviour_removal_allowed(&image, &system_root(), &program_files_folders()) {
            learn_and_quarantine(
                &image,
                threat_name,
                engine,
                quarantine,
                history,
                definition_generation,
            );
        }
    }
}

/// Logs a process start and hands it to the behaviour monitor, which keeps how each recent
/// process was started for the decisions made about it later.
fn record_process_start(
    notification: &BlackshardNotification,
    image: &Path,
    monitor: &Mutex<RansomwareMonitor>,
) {
    let command_line = notification_command_line(notification);
    log::info!(
        "Process {} started by {} (parent {}): {image:?} {command_line}",
        notification.process_id,
        notification.creating_process_id,
        notification.parent_process_id
    );
    if let Ok(mut monitor) = monitor.lock() {
        monitor.process_started(crate::behavior::ProcessStart {
            process_id: notification.process_id,
            process_start_key: notification.process_start_key,
            parent_process_id: notification.parent_process_id,
            creating_process_id: notification.creating_process_id,
            image: image.to_path_buf(),
            command_line,
        });
    }
}

pub(crate) fn notification_command_line(notification: &BlackshardNotification) -> String {
    let length = (notification.command_line_length as usize).min(MAX_COMMAND_LINE_LENGTH - 1);
    String::from_utf16_lossy(&notification.command_line[..length])
}

pub(crate) fn notification_path(notification: &BlackshardNotification) -> PathBuf {
    let path_length = (notification.path_length as usize).min(MAX_FILE_PATH_LENGTH - 1);
    PathBuf::from(String::from_utf16_lossy(
        &notification.file_path[..path_length],
    ))
}

pub(crate) fn valid_notification(notification: &BlackshardNotification) -> bool {
    // Scans need the file's identity. A protected-document change reported before the file is
    // open (a truncating open) has none, a process start has it only when the section scan left
    // it behind, and an image load never does.
    let identity_required = matches!(notification.operation, 1..=2);
    notification.magic == BLACKSHARD_PROTOCOL_MAGIC
        && notification.version == BLACKSHARD_PROTOCOL_VERSION
        && notification.size as usize == mem::size_of::<BlackshardNotification>()
        && matches!(notification.operation, 1..=6)
        && (!identity_required
            || (notification.file_id != 0 && notification.content_generation != 0))
        && notification.process_start_key != 0
        && notification.must_enforce
            == u32::from(notification.operation == OPERATION_EXECUTE_SECTION)
        && notification.reserved == 0
        && notification.reserved2 == 0
        && notification.path_length > 0
        && notification.path_length < MAX_FILE_PATH_LENGTH as u32
        && (notification.command_line_length as usize) < MAX_COMMAND_LINE_LENGTH
}

fn opened_final_path(file: &File) -> std::io::Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            file: isize,
            path: *mut u16,
            path_length: u32,
            flags: u32,
        ) -> u32;
    }

    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle() as isize, ptr::null_mut(), 0, 0) };
    if required == 0 || required > 32_767 {
        return Err(if required == 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the resolved file path exceeds Windows' long-path limit",
            )
        });
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as isize,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..written as usize],
    )))
}

/// `\Device\HarddiskVolumeN\Users\...` as `C:\Users\...`, for volumes with a drive letter.
fn device_path_to_dos_path(path: &Path) -> Option<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let text = path.to_string_lossy();
    for letter in b'A'..=b'Z' {
        let drive: Vec<u16> = [letter as u16, b':' as u16, 0].to_vec();
        let mut target = vec![0u16; 1024];
        let written =
            unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if written == 0 {
            continue;
        }
        // A list of NUL-terminated names; the first is the current mapping.
        let Some(device) = target
            .split(|unit| *unit == 0)
            .next()
            .and_then(|device| String::from_utf16(device).ok())
        else {
            continue;
        };
        if device.is_empty() || !text.is_char_boundary(device.len()) {
            continue;
        }
        let (head, rest) = text.split_at(device.len());
        if head.eq_ignore_ascii_case(&device) && rest.starts_with('\\') {
            return Some(PathBuf::from(format!("{}:{rest}", letter as char)));
        }
    }
    None
}

fn device_path_to_openable_path(path: &Path) -> PathBuf {
    let display = path.to_string_lossy();
    if display.starts_with("\\Device\\") {
        PathBuf::from(format!("\\\\?\\GLOBALROOT{display}"))
    } else {
        path.to_path_buf()
    }
}

pub(crate) fn hresult_text(hr: i32) -> String {
    match hr as u32 {
        0x8007_0002 => {
            "kernel communication port not found; the signed minifilter is not loaded".to_owned()
        }
        0x8007_0005 => {
            "filter port access denied; the background service must own the connection".to_owned()
        }
        code => format!("filter communication error 0x{code:08X}"),
    }
}

pub(crate) fn interruptible_wait(stop: &AtomicBool, duration: Duration) {
    let steps = (duration.as_millis() / 100).max(1);
    for _ in 0..steps {
        if stop.load(Ordering::Acquire) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn launch_hidden_probe(executable: &Path, argument: &str, path: &Path) -> std::io::Result<i32> {
    use std::os::windows::process::CommandExt;
    let status = std::process::Command::new(executable)
        .arg(argument)
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    Ok(status.code().unwrap_or(-1))
}

/// Windows binaries that are never terminated, even when they trip the ransomware heuristic.
///
/// Killing the shell, the search indexer or a service host takes down far more than the one
/// operation that was suspicious, and blocking the write has already stopped the damage. Matched
/// only for images inside `%SystemRoot%`, so a program that merely borrows one of these names is
/// not protected by it.
const NEVER_TERMINATE: &[&str] = &[
    "explorer.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "svchost.exe",
    "dllhost.exe",
];

/// Why a termination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpareReason {
    ReservedProcessId,
    Critical,
    ProtectedSystemBinary,
    /// Created after the event, so it is a different process that reused the ID.
    CreatedAfterEvent,
}

/// Decides whether a process that tripped the ransomware heuristic may be terminated.
///
/// Kept separate from the Windows calls so the policy can be tested directly.
fn termination_policy(
    process_id: u32,
    image: &Path,
    critical: bool,
    created_at: std::time::SystemTime,
    observed_at: std::time::SystemTime,
    system_root: &Path,
) -> Result<(), SpareReason> {
    if process_id == 0 || process_id == 4 || process_id == std::process::id() {
        return Err(SpareReason::ReservedProcessId);
    }
    let in_system_folder = in_protected_system_folder(image, system_root);
    if critical && in_system_folder {
        // Terminating a critical process bugchecks the machine. Anywhere else it is malware that
        // marked itself critical so that killing it crashes Windows; the flag is cleared before
        // it is terminated.
        return Err(SpareReason::Critical);
    }
    let reserved_name = image
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| NEVER_TERMINATE.contains(&name.to_ascii_lowercase().as_str()));
    if in_system_folder && reserved_name {
        return Err(SpareReason::ProtectedSystemBinary);
    }
    // ponytail: bounded by when the event was dequeued, not when it happened. A process ID reused
    // inside that queueing delay would still pass; having the driver send the requester's creation
    // time would close it exactly.
    if created_at > observed_at {
        return Err(SpareReason::CreatedAfterEvent);
    }
    Ok(())
}

/// Whether `image` sits directly in `%SystemRoot%`, `System32` or `SysWOW64`, which only
/// TrustedInstaller and administrators can write. A prefix match on `%SystemRoot%` is not enough:
/// a standard user can write `C:\Windows\Temp`, `C:\Windows\Tasks` and a few folders under
/// `System32`, and malware named `svchost.exe` there must not be spared.
fn in_protected_system_folder(image: &Path, system_root: &Path) -> bool {
    let Some(folder) = image.parent() else {
        return false;
    };
    let folder = folder.to_string_lossy().to_ascii_lowercase();
    let folder = folder.trim_end_matches('\\');
    let root = system_root.to_string_lossy().to_ascii_lowercase();
    let root = root.trim_end_matches('\\');
    folder == root || folder == format!(r"{root}\system32") || folder == format!(r"{root}\syswow64")
}

/// Whether a program convicted only by what it did, not by a signature, may be quarantined and
/// learned automatically. Only where a standard user or a download can put a program: anything
/// installed under Program Files or in Windows' own folders is stopped but left for a person to
/// judge, so a hijacked or abused installed program is not deleted, blocklisted machine-wide and
/// stripped of its services on the strength of 24 writes.
fn behaviour_removal_allowed(image: &Path, system_root: &Path, program_files: &[PathBuf]) -> bool {
    let lower = |path: &Path| PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
    let image = lower(image);
    if program_files
        .iter()
        .any(|folder| image.starts_with(lower(folder)))
    {
        return false;
    }
    let root = lower(system_root);
    if image.starts_with(&root) {
        // The parts of the Windows folder a standard user can write.
        return [
            r"temp",
            r"tasks",
            r"tracing",
            r"system32\tasks",
            r"system32\spool\drivers\color",
            r"syswow64\tasks",
        ]
        .iter()
        .any(|writable| image.starts_with(root.join(writable)));
    }
    true
}

fn program_files_folders() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

/// Terminates the process the ransomware heuristic blocked, unless the policy spares it, and
/// returns its image when it was terminated.
///
/// Only the ransomware path terminates on behaviour. The write that tripped the heuristic is
/// already denied; terminating the writer stops it moving on to the next file.
fn terminate_ransomware_process(
    process_id: u32,
    observed_at: std::time::SystemTime,
) -> Option<PathBuf> {
    terminate_if_allowed(process_id, observed_at, None)
}

/// Terminates every process running `image`, so a convicted file that is already running can be
/// removed: Windows refuses to delete an image that is mapped into a process. Returns how many
/// processes were terminated. The same policy spares Windows' own critical processes and the shell.
///
/// All of them are suspended before any is terminated, since show-off malware such as MEMZ runs
/// several copies that watch each other and crash Windows when one disappears. The documents each
/// one changed are then put back from the rollback vault.
pub(crate) fn terminate_processes_running(image: &Path) -> usize {
    let target = comparable_image_path(
        &std::fs::canonicalize(image).unwrap_or_else(|_| image.to_path_buf()),
    );
    let now = std::time::SystemTime::now();
    let targets = running_process_ids()
        .into_iter()
        .filter_map(|process_id| open_target(process_id, now, Some(&target)))
        .collect();
    let terminated = terminate_all(targets);
    for (process_id, created_at, _) in &terminated {
        undo_documents_changed_by(*process_id, *created_at);
    }
    terminated.len()
}

/// Puts back what a terminated program changed, from the copies the vault saved before it did.
fn undo_documents_changed_by(process_id: u32, created_at: std::time::SystemTime) {
    let Some(vault) = crate::rollback::global() else {
        return;
    };
    let summary = vault.restore_process_id(process_id, created_at, |folder| {
        crate::quarantine::pin_restore_directory(folder)
    });
    if summary.restored + summary.failed > 0 {
        log::warn!(
            "Documents changed by PID {process_id}: {} restored, {} not restored",
            summary.restored,
            summary.failed
        );
    }
}

/// The image of every running process this service can query, for a quick scan.
pub(crate) fn running_process_images() -> Vec<PathBuf> {
    let mut images = running_process_ids()
        .into_iter()
        .filter_map(process_image_path)
        .collect::<Vec<_>>();
    images.sort();
    images.dedup();
    images
}

/// The DLLs loaded into every running process this service can read, outside Windows' own
/// folders, for the turbo hunt.
pub(crate) fn running_process_modules() -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Threading::OpenProcess;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const LIST_MODULES_ALL: u32 = 0x03;
    #[link(name = "kernel32")]
    extern "system" {
        fn K32EnumProcessModulesEx(
            process: HANDLE,
            modules: *mut isize,
            size: u32,
            needed: *mut u32,
            filter: u32,
        ) -> i32;
        fn K32GetModuleFileNameExW(
            process: HANDLE,
            module: isize,
            name: *mut u16,
            size: u32,
        ) -> u32;
    }
    let system_root = system_root();
    let side_by_side = PathBuf::from(
        system_root
            .join("WinSxS")
            .to_string_lossy()
            .to_ascii_lowercase(),
    );
    let mut modules = Vec::new();
    for process_id in running_process_ids() {
        if process_id <= 4 {
            continue;
        }
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id) };
        if handle == 0 {
            continue;
        }
        let process = OwnedProcess(handle);
        let mut handles = vec![0isize; 1024];
        let mut needed = 0u32;
        let listed = unsafe {
            K32EnumProcessModulesEx(
                process.0,
                handles.as_mut_ptr(),
                (handles.len() * mem::size_of::<isize>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if listed == 0 {
            continue;
        }
        handles.truncate((needed as usize / mem::size_of::<isize>()).min(handles.len()));
        for module in handles {
            let mut name = vec![0u16; 32_768];
            let length = unsafe {
                K32GetModuleFileNameExW(process.0, module, name.as_mut_ptr(), name.len() as u32)
            } as usize;
            if length == 0 {
                continue;
            }
            let path = PathBuf::from(std::ffi::OsString::from_wide(&name[..length]));
            let lower = PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
            if in_protected_system_folder(&path, &system_root) || lower.starts_with(&side_by_side) {
                continue;
            }
            modules.push(path);
        }
    }
    modules.sort();
    modules.dedup();
    modules
}

pub(crate) fn running_process_ids() -> Vec<u32> {
    #[link(name = "kernel32")]
    extern "system" {
        fn K32EnumProcesses(process_ids: *mut u32, size: u32, returned: *mut u32) -> i32;
    }
    let mut process_ids = vec![0u32; 4096];
    loop {
        let size = (process_ids.len() * mem::size_of::<u32>()) as u32;
        let mut returned = 0u32;
        if unsafe { K32EnumProcesses(process_ids.as_mut_ptr(), size, &mut returned) } == 0 {
            return Vec::new();
        }
        // A full buffer may have been truncated, so retry with more room.
        if returned < size || process_ids.len() >= 1 << 20 {
            process_ids.truncate(returned as usize / mem::size_of::<u32>());
            return process_ids;
        }
        process_ids.resize(process_ids.len() * 2, 0);
    }
}

/// Lower-cased and without the `\\?\` prefix, so a canonical path compares with the Win32 path
/// `QueryFullProcessImageNameW` reports.
fn comparable_image_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy().to_lowercase();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

/// Terminates `process_id` unless the policy spares it or, when `expected_image` is given, it runs
/// a different image. Returns the image of a process it terminated.
fn terminate_if_allowed(
    process_id: u32,
    observed_at: std::time::SystemTime,
    expected_image: Option<&Path>,
) -> Option<PathBuf> {
    let target = open_target(process_id, observed_at, expected_image)?;
    terminate_all(vec![target])
        .into_iter()
        .next()
        .map(|(_, _, image)| image)
}

const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
/// `PROCESS_INFORMATION_CLASS::ProcessBreakOnTermination`: the critical-process flag.
const PROCESS_BREAK_ON_TERMINATION: u32 = 29;
const SE_DEBUG_PRIVILEGE: u32 = 20;
const SE_BACKUP_PRIVILEGE: u32 = 17;

/// Lets the service read files whatever their permissions say, with `FILE_FLAG_BACKUP_SEMANTICS`.
/// LocalSystem holds the privilege but it starts disabled.
pub(crate) fn enable_backup_privilege() {
    let mut previous = 0u8;
    let status = unsafe { RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, 1, 0, &mut previous) };
    if status < 0 {
        log::warn!(
            "SeBackupPrivilege could not be enabled (0x{status:08X}); files that deny SYSTEM read access cannot be scanned"
        );
    }
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
    fn NtSetInformationProcess(
        process: HANDLE,
        class: u32,
        information: *const c_void,
        length: u32,
    ) -> i32;
    fn RtlAdjustPrivilege(privilege: u32, enable: u8, current_thread: u8, previous: *mut u8)
        -> i32;
}

/// An open process handle, closed when dropped.
struct OwnedProcess(HANDLE);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// A process the termination policy allows, opened for suspending and terminating.
struct Target {
    process: OwnedProcess,
    process_id: u32,
    image: PathBuf,
    critical: bool,
    created_at: std::time::SystemTime,
}

fn process_image(handle: HANDLE) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
    let mut image = vec![0u16; 32_768];
    let mut length = image.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut length) } == 0 {
        return None;
    }
    image.truncate(length as usize);
    Some(PathBuf::from(std::ffi::OsString::from_wide(&image)))
}

/// When the process behind `handle` started.
pub(crate) fn process_start_time(handle: HANDLE) -> Option<std::time::SystemTime> {
    process_created_at(handle)
}

fn process_created_at(handle: HANDLE) -> Option<std::time::SystemTime> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    // FILETIME counts 100 ns intervals from 1601-01-01.
    Some(
        std::time::UNIX_EPOCH
            + Duration::from_nanos(ticks.saturating_sub(116_444_736_000_000_000) * 100),
    )
}

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Opens `process_id` if the policy lets it be terminated and, when `expected_image` is given, it
/// runs that image.
fn open_target(
    process_id: u32,
    observed_at: std::time::SystemTime,
    expected_image: Option<&Path>,
) -> Option<Target> {
    use windows_sys::Win32::System::Threading::{
        IsProcessCritical, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE
                | PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_SYNCHRONIZE
                | PROCESS_SUSPEND_RESUME
                | PROCESS_SET_INFORMATION,
            0,
            process_id,
        )
    };
    if handle == 0 {
        return None;
    }
    let process = OwnedProcess(handle);
    let spare = |reason: &str| {
        if expected_image.is_none() {
            log::warn!("Not terminating PID {process_id}: {reason}");
        }
        None
    };

    let Some(image) = process_image(handle) else {
        return spare("its image path could not be read");
    };
    // Canonical on both sides: a process started through an 8.3 name (C:\Users\RUNNER~1\...)
    // reports that short form, which never equals the long canonical path.
    if expected_image.is_some_and(|expected| {
        comparable_image_path(&std::fs::canonicalize(&image).unwrap_or_else(|_| image.clone()))
            != expected
    }) {
        return spare("it runs a different image");
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(handle, &mut critical) } == 0 {
        return spare("its critical status could not be read");
    }
    let Some(created_at) = process_created_at(handle) else {
        return spare("its creation time could not be read");
    };
    match termination_policy(
        process_id,
        &image,
        critical != 0,
        created_at,
        observed_at,
        &system_root(),
    ) {
        Ok(()) => Some(Target {
            process,
            process_id,
            image,
            critical: critical != 0,
            created_at,
        }),
        Err(reason) => spare(&format!("{reason:?} ({image:?})")),
    }
}

/// Clears the critical flag a program set on itself, so terminating it does not crash Windows.
fn clear_critical(handle: HANDLE) -> bool {
    use windows_sys::Win32::System::Threading::IsProcessCritical;
    let off = 0u32;
    let mut previous = 0u8;
    unsafe {
        // LocalSystem holds the debug privilege, but it is not enabled by default.
        RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &mut previous);
        NtSetInformationProcess(
            handle,
            PROCESS_BREAK_ON_TERMINATION,
            (&off as *const u32).cast(),
            mem::size_of::<u32>() as u32,
        );
        let mut critical = 1;
        IsProcessCritical(handle, &mut critical) != 0 && critical == 0
    }
}

/// Suspends every target first, so none can react to another's death, clears the critical flag
/// of those that set it, then terminates them. Returns each terminated process's ID, creation
/// time and image.
fn terminate_all(targets: Vec<Target>) -> Vec<(u32, std::time::SystemTime, PathBuf)> {
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
    for target in &targets {
        let status = unsafe { NtSuspendProcess(target.process.0) };
        if status < 0 {
            log::warn!(
                "Could not suspend PID {} before terminating it (0x{status:08X})",
                target.process_id
            );
        }
    }
    let mut terminated = Vec::new();
    for target in targets {
        if target.critical && !clear_critical(target.process.0) {
            // Left suspended: it does no harm frozen, and killing it would crash Windows.
            log::warn!(
                "Not terminating PID {} ({:?}): its critical flag could not be cleared; it stays suspended",
                target.process_id,
                target.image
            );
            continue;
        }
        if unsafe { TerminateProcess(target.process.0, 1) } == 0 {
            // Left suspended on purpose: a convicted program that cannot be killed does less
            // harm frozen than running.
            log::warn!(
                "Could not terminate PID {} ({:?}): {}; it stays suspended",
                target.process_id,
                target.image,
                std::io::Error::last_os_error()
            );
            continue;
        }
        terminated.push(target);
    }
    terminated
        .into_iter()
        .map(|target| {
            // Wait for the exit, so the image is unmapped by the time the caller deletes it.
            unsafe { WaitForSingleObject(target.process.0, 5_000) };
            log::warn!("Terminated PID {} ({:?})", target.process_id, target.image);
            (target.process_id, target.created_at, target.image.clone())
        })
        .collect()
}

/// Programs suspended at the start of a turbo hunt. Dropping this resumes the ones still running:
/// whatever the hunt convicted has been terminated by then.
pub(crate) struct Frozen(Vec<(u32, OwnedProcess)>);

impl Drop for Frozen {
    fn drop(&mut self) {
        for (_, process) in &self.0 {
            unsafe { NtResumeProcess(process.0) };
        }
    }
}

impl Frozen {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn process_ids(&self) -> Vec<u32> {
        self.0.iter().map(|(process_id, _)| *process_id).collect()
    }
}

/// Whether a program is one of Windows' own, sitting directly in the Windows folder, `System32`
/// or `SysWOW64`: the hunt stops injected threads in these rather than the whole process.
pub(crate) fn is_protected_system_image(image: &Path) -> bool {
    in_protected_system_folder(image, &system_root())
}

/// Stops one process under the same policy as everything else here (never Windows' critical
/// processes or the shell, all threads suspended first, a self-set critical flag cleared), and
/// puts back the documents it changed. Returns its image when it was stopped.
pub(crate) fn terminate_process(process_id: u32) -> Option<PathBuf> {
    let target = open_target(process_id, std::time::SystemTime::now(), None)?;
    let (process_id, created_at, image) = terminate_all(vec![target]).into_iter().next()?;
    undo_documents_changed_by(process_id, created_at);
    Some(image)
}

/// Suspends every program started since `since` that is not part of Windows, not blackshard and
/// not signed by a trusted publisher. Whatever was let in while protection was paused stops the
/// moment the hunt starts, before the scan has reached it, and cannot react as its copies are
/// convicted one by one.
pub(crate) fn freeze_programs_started_since(since: std::time::SystemTime) -> Frozen {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let system_root = comparable_image_path(&system_root());
    let own_folder = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(comparable_image_path));
    let mut frozen = Vec::new();
    for process_id in running_process_ids() {
        if process_id <= 4 || process_id == std::process::id() {
            continue;
        }
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME,
                0,
                process_id,
            )
        };
        if handle == 0 {
            continue;
        }
        let process = OwnedProcess(handle);
        if process_created_at(handle).is_none_or(|created| created < since) {
            continue;
        }
        let Some(image) = process_image(handle) else {
            continue;
        };
        let comparable = comparable_image_path(&image);
        if in_protected_system_folder(&image, &system_root)
            || own_folder
                .as_ref()
                .is_some_and(|folder| comparable.starts_with(folder))
            || trust::verify_file_cached(&image).is_trusted()
        {
            continue;
        }
        if unsafe { NtSuspendProcess(handle) } >= 0 {
            log::warn!("Froze PID {process_id} ({image:?}), started while protection was paused");
            frozen.push((process_id, process));
        }
    }
    Frozen(frozen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(image: &str, critical: bool, created_offset_ms: i64) -> Result<(), SpareReason> {
        let observed = std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let created = if created_offset_ms >= 0 {
            observed + Duration::from_millis(created_offset_ms as u64)
        } else {
            observed - Duration::from_millis(created_offset_ms.unsigned_abs())
        };
        termination_policy(
            4242,
            Path::new(image),
            critical,
            created,
            observed,
            Path::new(r"C:\Windows"),
        )
    }

    #[test]
    fn an_ordinary_encrypting_process_may_be_terminated() {
        assert_eq!(
            policy(r"C:\Users\x\Downloads\invoice.exe", false, -5_000),
            Ok(())
        );
        // Living-off-the-land tools are not spared just for living in System32.
        assert_eq!(
            policy(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                false,
                -5_000
            ),
            Ok(())
        );
    }

    #[test]
    fn critical_processes_and_the_shell_are_never_terminated() {
        assert_eq!(
            policy(r"C:\Windows\System32\csrss.exe", true, -5_000),
            Err(SpareReason::Critical)
        );
        assert_eq!(
            policy(r"C:\Windows\explorer.exe", false, -5_000),
            Err(SpareReason::ProtectedSystemBinary)
        );
        assert_eq!(
            policy(r"c:\windows\system32\SearchIndexer.EXE", false, -5_000),
            Err(SpareReason::ProtectedSystemBinary)
        );
    }

    #[test]
    fn user_writable_windows_folders_are_not_protected() {
        assert_eq!(
            policy(r"C:\Windows\Tasks\svchost.exe", false, -5_000),
            Ok(())
        );
        assert_eq!(
            policy(
                r"C:\Windows\System32\spool\drivers\color\csrss.exe",
                true,
                -5_000
            ),
            Ok(())
        );
        assert_eq!(
            policy(r"C:\Windows\SysWOW64\svchost.exe", false, -5_000),
            Err(SpareReason::ProtectedSystemBinary)
        );
    }

    #[test]
    fn behaviour_alone_removes_only_programs_in_user_writable_places() {
        let root = Path::new(r"C:\Windows");
        let program_files = [
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        let allowed =
            |image: &str| behaviour_removal_allowed(Path::new(image), root, &program_files);
        assert!(allowed(r"C:\Users\x\Downloads\invoice.exe"));
        assert!(allowed(r"C:\ProgramData\updater\svc.exe"));
        assert!(allowed(r"C:\Windows\Temp\x.exe"));
        assert!(allowed(r"D:\tools\x.exe"));
        assert!(!allowed(r"C:\Program Files\Editor\editor.exe"));
        assert!(!allowed(r"C:\Program Files (x86)\Old\old.exe"));
        assert!(!allowed(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
    }

    #[test]
    fn malware_that_marked_itself_critical_is_not_spared() {
        assert_eq!(policy(r"C:\Users\x\Desktop\MEMZ.exe", true, -5_000), Ok(()));
    }

    #[test]
    fn a_borrowed_system_name_outside_system_root_is_not_protected() {
        assert_eq!(
            policy(r"C:\Users\x\AppData\Local\Temp\explorer.exe", false, -5_000),
            Ok(())
        );
        assert_eq!(
            policy(r"C:\WindowsApps\explorer.exe", false, -5_000),
            Ok(())
        );
    }

    #[test]
    fn a_process_created_after_the_event_is_a_reused_id() {
        assert_eq!(
            policy(r"C:\Users\x\Downloads\invoice.exe", false, 250),
            Err(SpareReason::CreatedAfterEvent)
        );
    }

    #[test]
    fn reserved_process_ids_are_never_terminated() {
        let now = std::time::SystemTime::now();
        for process_id in [0, 4, std::process::id()] {
            assert_eq!(
                termination_policy(
                    process_id,
                    Path::new("x.exe"),
                    false,
                    now,
                    now,
                    Path::new(r"C:\Windows")
                ),
                Err(SpareReason::ReservedProcessId)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_live_process_is_spared_or_terminated_by_the_real_checks() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();

        // An event observed before this process existed cannot have been caused by it.
        terminate_ransomware_process(child.id(), std::time::UNIX_EPOCH);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            child.try_wait().unwrap().is_none(),
            "a reused ID was terminated"
        );

        terminate_ransomware_process(
            child.id(),
            std::time::SystemTime::now() + Duration::from_secs(1),
        );
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn notifications_need_a_file_identity_only_for_scans() {
        let notification = |operation: u32, file_id: u64| {
            let mut notification = unsafe { mem::zeroed::<BlackshardNotification>() };
            notification.magic = BLACKSHARD_PROTOCOL_MAGIC;
            notification.version = BLACKSHARD_PROTOCOL_VERSION;
            notification.size = mem::size_of::<BlackshardNotification>() as u16;
            notification.operation = operation;
            notification.must_enforce = u32::from(operation == OPERATION_EXECUTE_SECTION);
            notification.file_id = file_id;
            notification.content_generation = file_id;
            notification.process_start_key = 1;
            notification.path_length = 1;
            notification
        };
        for operation in [1, 2] {
            assert!(valid_notification(&notification(operation, 9)));
            assert!(!valid_notification(&notification(operation, 0)));
        }
        for operation in 3..=6 {
            assert!(valid_notification(&notification(operation, 0)));
        }
        assert!(!valid_notification(&notification(7, 9)));
        let mut enforced_open = notification(1, 9);
        enforced_open.must_enforce = 1;
        assert!(!valid_notification(&enforced_open));
    }

    #[test]
    fn device_paths_use_globalroot() {
        assert_eq!(
            device_path_to_openable_path(Path::new(r"\Device\HarddiskVolume3\sample.exe")),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume3\sample.exe")
        );
    }

    #[test]
    fn protocol_layout_matches_x64_filter_manager_abi() {
        assert_eq!(mem::size_of::<DriverControlRequest>(), 24);
        assert_eq!(mem::size_of::<DriverHealthReply>(), 160);
        assert_eq!(mem::size_of::<FilterMessageHeader>(), 16);
        assert_eq!(
            mem::offset_of!(BlackshardNotification, parent_process_id),
            2104
        );
        assert_eq!(mem::offset_of!(BlackshardNotification, command_line), 2120);
        assert_eq!(mem::size_of::<BlackshardNotification>(), 6216);
        assert_eq!(mem::size_of::<BlackshardMessage>(), 6232);
        assert_eq!(mem::size_of::<FilterReplyHeader>(), 16);
        assert_eq!(mem::size_of::<BlackshardReplyMessage>(), 32);
    }

    #[test]
    fn scan_failures_do_not_deny_program_execution() {
        let report = DetectionReport::error("scanner unavailable", Duration::ZERO);
        assert_eq!(execution_driver_verdict(&report), DriverVerdict::Allow);
    }

    #[test]
    fn execution_eligible_detections_deny_program_execution() {
        let mut report = DetectionReport::error("test", Duration::ZERO);
        report.execution_block_eligible = true;
        assert_eq!(execution_driver_verdict(&report), DriverVerdict::Block);
    }
}
