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
const BLACKSHARD_PROTOCOL_VERSION: u16 = 6;
const CONTROL_GET_HEALTH: u32 = 1;
const CONTROL_SET_READY_GENERATION: u32 = 2;
const OPERATION_PROTECTED_WRITE: u32 = 3;
const OPERATION_PROTECTED_METADATA: u32 = 4;
const MAX_FILE_PATH_LENGTH: usize = 1024;
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
    reserved: u32,
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
        let handle = self.port.swap(0, Ordering::AcqRel);
        if handle != 0 {
            unsafe { CloseHandle(handle) };
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn driver_health(&self) -> Result<DriverHealthCounters, String> {
        let port = self.port.load(Ordering::Acquire);
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
        })
    }

    pub fn set_ready_generation(&self, generation: u64) -> Result<(), String> {
        if generation == 0 {
            return Err("driver readiness generation zero is reserved".to_owned());
        }
        let port = self.port.load(Ordering::Acquire);
        if port == 0 {
            return Err("the kernel communication port is not connected".to_owned());
        }
        let request = DriverControlRequest {
            magic: BLACKSHARD_PROTOCOL_MAGIC,
            version: BLACKSHARD_PROTOCOL_VERSION,
            size: mem::size_of::<DriverControlRequest>() as u16,
            command: CONTROL_SET_READY_GENERATION,
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
            return Err("the minifilter returned unexpected readiness data".to_owned());
        }
        Ok(())
    }
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
        let enabled = settings
            .read()
            .map(|value| value.real_time_protection && !value.is_excluded(&openable_path))
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

        // There is no cache lookup before the file is opened. The driver reports a file ID but no
        // volume, and NTFS file IDs repeat across volumes, so an ID-only hit could allow a file on
        // a removable drive unscanned on the strength of a clean verdict cached for C:. Opening
        // the file yields its full identity, and the exact-key lookup below still avoids a rescan.
        // Restoring a pre-open fast path needs the volume serial added to the driver notification.
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
                                        DetectionVerdict::Suspicious => CacheVerdict::Suspicious,
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
                                    execution_block_eligible: scan_result.execution_block_eligible,
                                },
                            );
                        }
                        scan_result
                    }
                }
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
                        Some(notification.file_id),
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

        if let Ok(mut value) = counters.lock() {
            value.scanned += 1;
            match report.verdict {
                DetectionVerdict::Clean => {}
                DetectionVerdict::Suspicious => value.suspicious += 1,
                DetectionVerdict::Malicious => value.detected += 1,
                DetectionVerdict::Error => value.scan_errors += 1,
            }
            if driver_verdict == DriverVerdict::Block && reply_accepted {
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
                "block_reply_accepted={reply_accepted}; pid={}",
                item.message.notification.process_id
            ));
            let _ = history.append(&event);
        }

        if report.verdict != DetectionVerdict::Clean {
            let _ = events.try_send(RealtimeEvent::Decision(Box::new(RealtimeDecision {
                process_id: notification.process_id,
                path,
                report,
                block_reply_accepted: driver_verdict == DriverVerdict::Block && reply_accepted,
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
    let (enabled, block_mode, keep_copies) = settings
        .read()
        .map(|settings| {
            (
                settings.real_time_protection
                    && settings.ransomware_protection
                    && !settings.is_excluded(path),
                settings.ransomware_block_mode,
                settings.rollback_documents,
            )
        })
        .unwrap_or((false, false, false));
    if !enabled {
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
        if let Some(vault) = crate::rollback::global() {
            vault.preserve(
                (notification.process_id, notification.process_start_key),
                path,
            );
        }
    }
    let decision = monitor
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
            learn_and_quarantine(&image, engine, quarantine, history, definition_generation);
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
        crate::quarantine::pin_restore_directory(folder).map(drop)
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
    engine: &SharedDetectionEngine,
    quarantine: &QuarantineStore,
    history: &EventHistory,
    definition_generation: &AtomicU64,
) {
    const THREAT_NAME: &str = "Shard.Behavior.Ransomware";
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
    match crate::shards::learn(sha256, THREAT_NAME) {
        // Cached clean verdicts for this file are stale now.
        Ok(_) => {
            definition_generation.fetch_add(1, Ordering::AcqRel);
        }
        Err(error) => log::warn!("Could not learn a shard for {image:?}: {error}"),
    }
    let (kind, summary, details) = match quarantine.quarantine_verified(
        image,
        THREAT_NAME,
        100,
        sha256,
        report.file_size,
        None,
    ) {
        Ok(record) if record.state == IsolationState::Isolated => (
            EventKind::Quarantined,
            "Ransomware program stopped, learned and moved to quarantine",
            record.cleanup_summary(),
        ),
        Ok(_) => (
            EventKind::QuarantineFailed,
            "Ransomware program stopped and learned; its file could not be removed",
            None,
        ),
        Err(error) => (
            EventKind::QuarantineFailed,
            "Ransomware program stopped and learned; quarantine failed",
            Some(error.to_string()),
        ),
    };
    let mut event = SecurityEvent::new(kind, summary);
    event.path = Some(image.to_path_buf());
    event.threat_name = Some(THREAT_NAME.to_owned());
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

fn process_image_path(process_id: u32) -> Option<PathBuf> {
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

pub(crate) fn notification_path(notification: &BlackshardNotification) -> PathBuf {
    let path_length = (notification.path_length as usize).min(MAX_FILE_PATH_LENGTH - 1);
    PathBuf::from(String::from_utf16_lossy(
        &notification.file_path[..path_length],
    ))
}

pub(crate) fn valid_notification(notification: &BlackshardNotification) -> bool {
    notification.magic == BLACKSHARD_PROTOCOL_MAGIC
        && notification.version == BLACKSHARD_PROTOCOL_VERSION
        && notification.size as usize == mem::size_of::<BlackshardNotification>()
        && matches!(notification.operation, 1..=4)
        && notification.file_id != 0
        && notification.content_generation != 0
        && notification.process_start_key != 0
        && ((notification.operation == 1 && notification.must_enforce == 0)
            || (notification.operation == 2 && notification.must_enforce == 1)
            || (matches!(notification.operation, 3..=4) && notification.must_enforce == 0))
        && notification.reserved == 0
        && notification.path_length > 0
        && notification.path_length < MAX_FILE_PATH_LENGTH as u32
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
    if critical {
        // Terminating a critical process bugchecks the machine.
        return Err(SpareReason::Critical);
    }
    // Compared component by component, so `C:\WindowsApps` does not count as `C:\Windows`.
    let in_system_root = PathBuf::from(image.to_string_lossy().to_ascii_lowercase())
        .starts_with(system_root.to_string_lossy().to_ascii_lowercase());
    let reserved_name = image
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| NEVER_TERMINATE.contains(&name.to_ascii_lowercase().as_str()));
    if in_system_root && reserved_name {
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
/// processes were terminated. The same policy spares critical processes and the shell.
pub(crate) fn terminate_processes_running(image: &Path) -> usize {
    let target = comparable_image_path(
        &std::fs::canonicalize(image).unwrap_or_else(|_| image.to_path_buf()),
    );
    let now = std::time::SystemTime::now();
    running_process_ids()
        .into_iter()
        .filter(|process_id| terminate_if_allowed(*process_id, now, Some(&target)).is_some())
        .count()
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

fn running_process_ids() -> Vec<u32> {
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
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, IsProcessCritical, OpenProcess, QueryFullProcessImageNameW,
            TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        let handle = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            process_id,
        );
        if handle == 0 {
            return None;
        }
        let close = |reason: &str| {
            if expected_image.is_none() {
                log::warn!("Not terminating PID {process_id}: {reason}");
            }
            CloseHandle(handle);
            None
        };

        let mut image = vec![0u16; 32_768];
        let mut length = image.len() as u32;
        if QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut length) == 0 {
            return close("its image path could not be read");
        }
        image.truncate(length as usize);
        let image = PathBuf::from(std::ffi::OsString::from_wide(&image));
        // Canonical on both sides: a process started through an 8.3 name (C:\Users\RUNNER~1\...)
        // reports that short form, which never equals the long canonical path.
        if expected_image.is_some_and(|expected| {
            comparable_image_path(&std::fs::canonicalize(&image).unwrap_or_else(|_| image.clone()))
                != expected
        }) {
            return close("it runs a different image");
        }

        let mut critical = 0;
        if IsProcessCritical(handle, &mut critical) == 0 {
            return close("its critical status could not be read");
        }

        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
            return close("its creation time could not be read");
        }
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        // FILETIME counts 100 ns intervals from 1601-01-01.
        let created_at = std::time::UNIX_EPOCH
            + Duration::from_nanos(ticks.saturating_sub(116_444_736_000_000_000) * 100);

        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        match termination_policy(
            process_id,
            &image,
            critical != 0,
            created_at,
            observed_at,
            &system_root,
        ) {
            Ok(()) => {
                let terminated = TerminateProcess(handle, 1) != 0;
                // Wait for the exit, so the image is unmapped by the time the caller deletes it.
                if terminated {
                    WaitForSingleObject(handle, 5_000);
                }
                CloseHandle(handle);
                log::warn!("Terminated PID {process_id} ({image:?})");
                terminated.then_some(image)
            }
            Err(reason) => close(&format!("{reason:?} ({image:?})")),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (process_id, observed_at, expected_image);
        None
    }
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
        assert_eq!(mem::size_of::<BlackshardNotification>(), 2104);
        assert_eq!(mem::size_of::<BlackshardMessage>(), 2120);
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
