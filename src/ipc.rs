use crate::config::Settings;
use crate::detection::DetectionVerdict;
use crate::history::SecurityEvent;
use crate::quarantine::{IsolationState, QuarantineRecord};
use crate::scan_manager::{ScanKind, ScanPhase, ScanProgress};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use uuid::Uuid;

pub const IPC_PROTOCOL_VERSION: u32 = 1;
pub const AMSI_IPC_PROTOCOL_VERSION: u32 = 1;
pub const PIPE_NAME: &str = r"\\.\pipe\BlackshardProtection-v1";
pub const AMSI_PIPE_NAME: &str = r"\\.\pipe\BlackshardAmsi-v1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_AMSI_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_AMSI_REQUEST_BYTES: usize = MAX_AMSI_CONTENT_BYTES + 16 * 1024;
const MAX_AMSI_CHUNK_BYTES: usize = 64 * 1024;
const MAX_AMSI_CHUNKS: usize = MAX_AMSI_CONTENT_BYTES / MAX_AMSI_CHUNK_BYTES;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_CUSTOM_SCAN_ROOTS: usize = 16;
const MAX_QUARANTINE_RESULTS: usize = 256;
const MAX_ACTIVITY_RESULTS: usize = 200;
const MAX_SCAN_FINDINGS: usize = 128;
const MAX_WIRE_PATH_CHARS: usize = 768;
const MAX_WIRE_TEXT_CHARS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    version: u32,
    request_id: Uuid,
    command: RpcCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    version: u32,
    request_id: Uuid,
    result: RpcResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AmsiRequestEnvelope {
    version: u32,
    request_id: Uuid,
    session_id: Uuid,
    application_name: String,
    content_name: String,
    content_type: String,
    chunks: Vec<Vec<u8>>,
    finalize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AmsiResponseEnvelope {
    version: u32,
    request_id: Uuid,
    result: AmsiResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum AmsiResult {
    Verdict { verdict: DetectionVerdictView },
    Error { code: RpcErrorCode, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum RpcCommand {
    Ping,
    GetSettings,
    SaveSettings {
        settings: Settings,
    },
    StartScan {
        kind: ScanRequestKind,
        roots: Vec<String>,
    },
    ScanStatus {
        scan_id: Uuid,
    },
    CancelScan {
        scan_id: Uuid,
    },
    ListQuarantine,
    RestoreQuarantine {
        id: Uuid,
    },
    DeleteQuarantine {
        id: Uuid,
    },
    RecentActivity {
        limit: usize,
    },
    ClearActivity,
    RequestUpdate,
    RunSelfTest,
    CheckForUpdates,
    GetFreshClamStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedClientComponent {
    DesktopUi,
    ElevatedHelper,
    NotificationAgent,
    AmsiHost,
    Unknown,
}

fn component_allows_command(component: TrustedClientComponent, command: &RpcCommand) -> bool {
    use RpcCommand::*;
    match component {
        TrustedClientComponent::DesktopUi => matches!(
            command,
            Ping | GetSettings
                | StartScan { .. }
                | ScanStatus { .. }
                | CancelScan { .. }
                | ListQuarantine
                | RecentActivity { .. }
                | RequestUpdate
                | RunSelfTest
                | CheckForUpdates
                | GetFreshClamStatus
        ),
        TrustedClientComponent::ElevatedHelper => true,
        TrustedClientComponent::NotificationAgent => {
            matches!(command, Ping | RecentActivity { .. })
        }
        TrustedClientComponent::AmsiHost => false,
        TrustedClientComponent::Unknown => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RpcResult {
    Success { response: RpcResponse },
    Error { code: RpcErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    AccessDenied,
    Busy,
    InvalidRequest,
    NotFound,
    NotConfigured,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshClamStatusView {
    pub engine_version: String,
    pub database_version: String,
    pub database_age_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
enum RpcResponse {
    Pong,
    Acknowledged { message: String },
    Settings { settings: Settings },
    ScanProgress { progress: ScanProgressView },
    Quarantine { records: Vec<QuarantineRecordView> },
    Activity { events: Vec<SecurityEvent> },
    FreshClamStatus { status: FreshClamStatusView },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScanRequestKind {
    Quick,
    /// A quick scan at full speed: every core, no low-resource pauses. For when a threat is
    /// already loose and finding it now matters more than the machine staying responsive.
    Turbo,
    Full,
    Custom {
        roots: Vec<String>,
    },
}

impl ScanRequestKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Quick => "Quick scan",
            Self::Turbo => "Turbo scan",
            Self::Full => "Full scan",
            Self::Custom { .. } => "Custom scan",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhaseView {
    Enumerating,
    Scanning,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

impl ScanPhaseView {
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionVerdictView {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFindingView {
    pub path: String,
    pub verdict: DetectionVerdictView,
    pub risk_score: u8,
    pub confidence: u8,
    pub threat_name: Option<String>,
    pub quarantine_state: Option<IsolationState>,
    pub action_error: Option<String>,
    pub analysis_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanProgressView {
    pub id: Uuid,
    pub kind: ScanRequestKind,
    pub phase: ScanPhaseView,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub current_path: Option<String>,
    pub discovered_files: u64,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub clean_files: u64,
    pub suspicious_files: u64,
    pub malicious_files: u64,
    pub quarantined_files: u64,
    pub errors: u64,
    pub findings: Vec<ScanFindingView>,
    pub elapsed_millis: u64,
    pub failure: Option<String>,
}

impl ScanProgressView {
    pub fn is_finished(&self) -> bool {
        self.phase.is_finished()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecordView {
    pub id: Uuid,
    pub original_path: String,
    pub quarantined_at: DateTime<Utc>,
    pub sha256: String,
    pub size: u64,
    pub threat_name: String,
    pub risk_score: u8,
    pub state: IsolationState,
}

impl From<&QuarantineRecord> for QuarantineRecordView {
    fn from(record: &QuarantineRecord) -> Self {
        Self {
            id: record.id,
            original_path: bounded_string(
                record.original_path.to_string_lossy(),
                MAX_WIRE_PATH_CHARS,
            ),
            quarantined_at: record.quarantined_at,
            sha256: record.sha256.clone(),
            size: record.size,
            threat_name: bounded_string(&record.threat_name, 128),
            risk_score: record.risk_score,
            state: record.state,
        }
    }
}

impl From<&ScanProgress> for ScanProgressView {
    fn from(progress: &ScanProgress) -> Self {
        let kind = match &progress.kind {
            ScanKind::Quick => ScanRequestKind::Quick,
            ScanKind::Full => ScanRequestKind::Full,
            ScanKind::Custom(roots) => ScanRequestKind::Custom {
                roots: roots
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
            },
        };
        let phase = match progress.phase {
            ScanPhase::Enumerating => ScanPhaseView::Enumerating,
            ScanPhase::Scanning => ScanPhaseView::Scanning,
            ScanPhase::Cancelling => ScanPhaseView::Cancelling,
            ScanPhase::Completed => ScanPhaseView::Completed,
            ScanPhase::Cancelled => ScanPhaseView::Cancelled,
            ScanPhase::Failed => ScanPhaseView::Failed,
        };
        let findings = progress
            .findings
            .iter()
            .take(MAX_SCAN_FINDINGS)
            .map(|finding| ScanFindingView {
                path: bounded_string(finding.path.to_string_lossy(), MAX_WIRE_PATH_CHARS),
                verdict: match finding.report.verdict {
                    DetectionVerdict::Clean => DetectionVerdictView::Clean,
                    DetectionVerdict::Suspicious => DetectionVerdictView::Suspicious,
                    DetectionVerdict::Malicious => DetectionVerdictView::Malicious,
                    DetectionVerdict::Error => DetectionVerdictView::Error,
                },
                risk_score: finding.report.risk_score,
                confidence: finding.report.confidence,
                threat_name: finding
                    .report
                    .threat_name
                    .as_deref()
                    .map(|value| bounded_string(value, 128)),
                quarantine_state: finding.quarantine.as_ref().map(|record| record.state),
                action_error: finding
                    .action_error
                    .as_deref()
                    .map(|value| bounded_string(value, MAX_WIRE_TEXT_CHARS)),
                analysis_error: finding
                    .report
                    .error
                    .as_deref()
                    .map(|value| bounded_string(value, MAX_WIRE_TEXT_CHARS)),
            })
            .collect();
        Self {
            id: progress.id,
            kind,
            phase,
            started_at: progress.started_at,
            finished_at: progress.finished_at,
            current_path: progress
                .current_path
                .as_ref()
                .map(|path| bounded_string(path.to_string_lossy(), MAX_WIRE_PATH_CHARS)),
            discovered_files: progress.discovered_files,
            scanned_files: progress.scanned_files,
            scanned_bytes: progress.scanned_bytes,
            clean_files: progress.clean_files,
            suspicious_files: progress.suspicious_files,
            malicious_files: progress.malicious_files,
            quarantined_files: progress.quarantined_files,
            errors: progress.errors,
            findings,
            elapsed_millis: progress.elapsed.as_millis().min(u64::MAX as u128) as u64,
            failure: progress.failure.clone(),
        }
    }
}

impl ScanProgressView {
    fn from_with_requested_kind(progress: &ScanProgress, kind: ScanRequestKind) -> Self {
        let mut view = Self::from(progress);
        view.kind = match kind {
            ScanRequestKind::Custom { .. } => ScanRequestKind::Custom { roots: Vec::new() },
            other => other,
        };
        view
    }
}

fn bounded_string(value: impl AsRef<str>, maximum_chars: usize) -> String {
    let value = value.as_ref();
    if value.chars().count() <= maximum_chars {
        value.to_owned()
    } else {
        let mut truncated: String = value
            .chars()
            .take(maximum_chars.saturating_sub(3))
            .collect();
        truncated.push_str("...");
        truncated
    }
}

fn requires_elevated_admin(command: &RpcCommand) -> bool {
    matches!(
        command,
        RpcCommand::SaveSettings { .. }
            | RpcCommand::RestoreQuarantine { .. }
            | RpcCommand::DeleteQuarantine { .. }
            | RpcCommand::ClearActivity
    )
}

const SERVICE_UNAVAILABLE: &str = "protection service is unavailable";

#[derive(Debug, Clone)]
pub struct RpcFailure {
    pub code: RpcErrorCode,
    pub message: String,
}

impl std::fmt::Display for RpcFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for RpcFailure {}

impl RpcFailure {
    /// Whether the call failed because the service could not be reached at all, as opposed to
    /// the service answering with an error.
    pub fn is_service_unavailable(&self) -> bool {
        self.message.starts_with(SERVICE_UNAVAILABLE)
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::Internal,
            message: message.into(),
        }
    }
}

#[cfg(windows)]
mod windows_transport {
    use super::*;
    use crate::history::{EventHistory, EventKind, SecurityEvent};
    use crate::quarantine::QuarantineStore;
    use crate::realtime::SharedDetectionEngine;
    use crate::scan_manager::ScanJob;
    use std::ffi::{c_void, OsStr, OsString};
    use std::fs;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::{SyncSender, TrySendError};
    use std::sync::RwLock;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_NO_DATA,
        ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation,
        IsValidSid, RevertToSelf, SecurityIdentification, TokenElevation, TokenImpersonationLevel,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        ImpersonateNamedPipeClient, PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW,
        PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const IO_TIMEOUT: Duration = Duration::from_secs(3);
    const PIPE_DEFAULT_TIMEOUT_MS: u32 = 3_000;
    // Non-admin callers get `FILE_GENERIC_READ | FILE_WRITE_DATA` (0x12008b) rather than
    // `GENERIC_WRITE`. On a pipe, `GENERIC_WRITE` includes `FILE_CREATE_PIPE_INSTANCE`, which would
    // let any caller add a rogue server instance alongside the real ones; every instance shares
    // this descriptor, so the owner check in `verify_pipe_owner` could not tell the two apart.
    //
    // `OW` grants the pipe's owner, whoever created the first instance, the right to add the rest
    // of the pool. For the service that is SYSTEM, which already holds `GA` anyway.
    const CLIENT_PIPE_ACCESS: u32 = 0x0012_008b;
    const MANAGEMENT_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;IU)";
    const AMSI_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;AU)";

    /// Concurrent AMSI requests the service can serve.
    ///
    /// AMSI is the only real-time layer without the minifilter, and a single instance let a burst
    /// of scripts queue past the client's wait budget, at which point the provider fails open.
    // ponytail: fixed pool; size it from the core count if scanning ever becomes the bottleneck.
    const AMSI_INSTANCES: usize = 8;

    /// How long an AMSI client may take to send its request, or hold the instance afterwards.
    ///
    /// Genuine clients write as soon as they connect, so this only bounds how long an idle or
    /// hostile connection can keep one of the pool's instances away from everyone else.
    const AMSI_IO_TIMEOUT: Duration = Duration::from_millis(500);

    #[derive(Clone)]
    pub struct RpcServiceResources {
        pub engine: SharedDetectionEngine,
        pub quarantine: Arc<QuarantineStore>,
        pub history: Arc<EventHistory>,
        pub settings: Arc<RwLock<Settings>>,
        pub settings_path: PathBuf,
        pub update_requests: SyncSender<()>,
        pub updates_configured: bool,
        scan: Arc<Mutex<Option<ActiveScan>>>,
    }

    struct ActiveScan {
        job: ScanJob,
        requested_kind: ScanRequestKind,
        owner_sid: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct CallerContext {
        sid: Vec<u8>,
        elevated_admin: bool,
        component: TrustedClientComponent,
    }

    impl RpcServiceResources {
        pub fn new(
            engine: SharedDetectionEngine,
            quarantine: Arc<QuarantineStore>,
            history: Arc<EventHistory>,
            settings: Arc<RwLock<Settings>>,
            settings_path: PathBuf,
            update_requests: SyncSender<()>,
            updates_configured: bool,
        ) -> Self {
            Self {
                engine,
                quarantine,
                history,
                settings,
                settings_path,
                update_requests,
                updates_configured,
                scan: Arc::new(Mutex::new(None)),
            }
        }
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> io::Result<Self> {
            if handle == 0 || handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct SecurityDescriptor(*mut c_void);

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    struct RevertGuard;

    impl Drop for RevertGuard {
        fn drop(&mut self) {
            unsafe {
                RevertToSelf();
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Endpoint {
        Management,
        Amsi,
    }

    impl Endpoint {
        fn pipe_name(self) -> &'static str {
            match self {
                Self::Management => PIPE_NAME,
                Self::Amsi => AMSI_PIPE_NAME,
            }
        }

        fn max_request_bytes(self) -> usize {
            match self {
                Self::Management => MAX_REQUEST_BYTES,
                Self::Amsi => MAX_AMSI_REQUEST_BYTES,
            }
        }

        fn instances(self) -> usize {
            match self {
                // The UI and a handful of commands; one instance is plenty.
                Self::Management => 1,
                Self::Amsi => AMSI_INSTANCES,
            }
        }

        fn io_timeout(self) -> Duration {
            match self {
                Self::Management => IO_TIMEOUT,
                Self::Amsi => AMSI_IO_TIMEOUT,
            }
        }
    }

    pub struct RpcServer {
        stop: Arc<AtomicBool>,
        workers: Vec<(Endpoint, JoinHandle<()>)>,
    }

    impl RpcServer {
        pub fn start(resources: RpcServiceResources) -> Result<Self, String> {
            let stop = Arc::new(AtomicBool::new(false));
            let mut workers = Vec::new();

            // Instances start one at a time. The first of each endpoint must exist before its
            // siblings: only the first uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, and a sibling racing
            // ahead would take the name and make that first create fail.
            for endpoint in [Endpoint::Management, Endpoint::Amsi] {
                for instance in 0..endpoint.instances() {
                    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
                    let worker_resources = resources.clone();
                    let worker_stop = Arc::clone(&stop);
                    let spawned = thread::Builder::new()
                        .name(format!("blackshard-{endpoint:?}-rpc-{instance}").to_lowercase())
                        .spawn(move || {
                            server_loop(
                                worker_resources,
                                worker_stop,
                                ready_sender,
                                endpoint,
                                instance == 0,
                            )
                        });
                    let worker = match spawned {
                        Ok(worker) => worker,
                        Err(error) => {
                            stop_workers(&stop, workers);
                            return Err(format!(
                                "could not start the {endpoint:?} server: {error}"
                            ));
                        }
                    };
                    workers.push((endpoint, worker));

                    let failure = match ready_receiver.recv_timeout(IO_TIMEOUT) {
                        Ok(Ok(())) => None,
                        Ok(Err(error)) => Some(error),
                        Err(error) => Some(format!(
                            "the {endpoint:?} server did not initialize in time: {error}"
                        )),
                    };
                    if let Some(error) = failure {
                        stop_workers(&stop, workers);
                        return Err(error);
                    }
                }
            }
            Ok(Self { stop, workers })
        }

        pub fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            stop_workers(&self.stop, std::mem::take(&mut self.workers));
        }
    }

    /// Signals every listener to stop and waits for them to exit.
    ///
    /// Each instance may be parked in `ConnectNamedPipe`, so each needs its own connection to wake
    /// it. Pokes repeat until every worker has exited, because an instance that was busy when
    /// `stop` was set only starts listening again, and so only becomes wakeable, afterwards.
    fn stop_workers(stop: &AtomicBool, workers: Vec<(Endpoint, JoinHandle<()>)>) {
        stop.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while workers.iter().any(|(_, worker)| !worker.is_finished()) && Instant::now() < deadline {
            for (endpoint, worker) in &workers {
                if !worker.is_finished() {
                    poke_listener(endpoint.pipe_name());
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        for (endpoint, worker) in workers {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                log::warn!("a {endpoint:?} listener did not stop within 5 seconds");
            }
        }
    }

    impl Drop for RpcServer {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    fn server_loop(
        resources: RpcServiceResources,
        stop: Arc<AtomicBool>,
        ready: SyncSender<Result<(), String>>,
        endpoint: Endpoint,
        first: bool,
    ) {
        // The instance is created once and reused for every client. Dropping and recreating it
        // after each request left moments where the pipe name did not exist at all, and any local
        // user could claim it in that gap.
        let pipe = match create_server_pipe_with_retry(endpoint, first) {
            Ok(pipe) => pipe,
            Err(detail) => {
                let _ = ready.send(Err(detail));
                return;
            }
        };
        let _ = ready.send(Ok(()));

        let blocking = PIPE_READMODE_BYTE | PIPE_WAIT;
        while !stop.load(Ordering::Acquire) {
            // The previous client left the handle non-blocking, and in that mode
            // `ConnectNamedPipe` returns immediately instead of waiting.
            unsafe {
                SetNamedPipeHandleState(pipe.raw(), &blocking, null(), null());
            }

            let connected = unsafe { ConnectNamedPipe(pipe.raw(), null_mut()) } != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected {
                if !stop.load(Ordering::Acquire) {
                    log::debug!(
                        "local control connection failed: {}",
                        io::Error::last_os_error()
                    );
                    // A client that connected and left before we noticed leaves the instance in a
                    // state that only a disconnect clears.
                    unsafe {
                        DisconnectNamedPipe(pipe.raw());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                continue;
            }
            if stop.load(Ordering::Acquire) {
                unsafe {
                    DisconnectNamedPipe(pipe.raw());
                }
                break;
            }

            let nonblocking = PIPE_READMODE_BYTE | PIPE_NOWAIT;
            if unsafe { SetNamedPipeHandleState(pipe.raw(), &nonblocking, null(), null()) } == 0 {
                append_rpc_error(
                    &resources.history,
                    &format!(
                        "could not apply bounded local pipe mode: {}",
                        io::Error::last_os_error()
                    ),
                );
                unsafe {
                    DisconnectNamedPipe(pipe.raw());
                }
                continue;
            }

            let handled = match authorize_client(pipe.raw(), endpoint) {
                Ok(caller) => {
                    log::debug!(
                        "IPC client connected and authorized: component {:?}, SID {:?}",
                        caller.component,
                        caller.sid
                    );
                    match endpoint {
                        Endpoint::Management => {
                            process_one_request(pipe.raw(), &resources, &caller).and_then(
                                |envelope| {
                                    write_json_frame(pipe.raw(), &envelope, MAX_RESPONSE_BYTES)
                                        .map_err(|error| {
                                            RpcFailure::transport(format!(
                                                "could not write management response: {error}"
                                            ))
                                        })
                                },
                            )
                        }
                        Endpoint::Amsi => process_one_amsi_request(pipe.raw(), &resources, &caller)
                            .and_then(|envelope| {
                                write_json_frame(pipe.raw(), &envelope, MAX_RESPONSE_BYTES).map_err(
                                    |error| {
                                        RpcFailure::transport(format!(
                                            "could not write AMSI response: {error}"
                                        ))
                                    },
                                )
                            }),
                    }
                }
                Err(error) => {
                    log::error!("IPC client authentication failed: {error}");
                    Err(RpcFailure {
                        code: RpcErrorCode::AccessDenied,
                        message: format!("local client authentication failed: {error}"),
                    })
                }
            };
            if handled.is_ok() {
                let mut dummy = [0u8; 1];
                let _ = read_exact_until(
                    pipe.raw(),
                    &mut dummy,
                    Instant::now() + endpoint.io_timeout(),
                );
            }
            unsafe {
                DisconnectNamedPipe(pipe.raw());
            }
            log::debug!("IPC client disconnected");
        }
    }

    /// Creates an instance, retrying briefly while a previous service process releases the name.
    ///
    /// A first instance that still cannot be created after that means another process holds the
    /// name. That is reported as a startup failure instead of being retried forever, which is what
    /// used to happen and what left a squatter in control indefinitely.
    fn create_server_pipe_with_retry(
        endpoint: Endpoint,
        first: bool,
    ) -> Result<OwnedHandle, String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match create_server_pipe(endpoint, first) {
                Ok(pipe) => return Ok(pipe),
                Err(error) if error.raw_os_error() == Some(5) && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) if error.raw_os_error() == Some(5) => {
                    return Err(format!(
                        "the {endpoint:?} pipe name is already owned by another process: {error}"
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "could not create protected {endpoint:?} local pipe: {error}"
                    ))
                }
            }
        }
    }

    fn create_server_pipe(endpoint: Endpoint, first: bool) -> io::Result<OwnedHandle> {
        let mut descriptor = null_mut();
        let sddl = wide(match endpoint {
            Endpoint::Management => MANAGEMENT_SDDL,
            Endpoint::Amsi => AMSI_SDDL,
        });
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = SecurityDescriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide(endpoint.pipe_name());
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                endpoint.instances() as u32,
                MAX_RESPONSE_BYTES as u32,
                endpoint.max_request_bytes() as u32,
                PIPE_DEFAULT_TIMEOUT_MS,
                &attributes,
            )
        };
        OwnedHandle::new(handle)
    }

    fn authorize_client(pipe: HANDLE, endpoint: Endpoint) -> io::Result<CallerContext> {
        let mut caller = authenticate_pipe_token(pipe)?;

        let mut process_id = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedHandle::new(unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id)
        })?;
        let mut image = vec![0u16; 32_768];
        let mut length = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.raw(), 0, image.as_mut_ptr(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        image.truncate(length as usize);
        let client_path = PathBuf::from(OsString::from_wide(&image));
        if matches!(endpoint, Endpoint::Amsi) {
            let client_path = fs::canonicalize(client_path)?;
            let metadata = fs::symlink_metadata(client_path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the AMSI host identity is not a regular executable",
                ));
            }
            caller.component = TrustedClientComponent::AmsiHost;
            return Ok(caller);
        }
        let service_path = std::env::current_exe()?;
        caller.component =
            classify_installed_component(&client_path, &service_path, caller.elevated_admin)?;
        if caller.component == TrustedClientComponent::Unknown {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the caller is not an authorized installed blackshard component",
            ));
        }
        Ok(caller)
    }

    fn authenticate_pipe_token(pipe: HANDLE) -> io::Result<CallerContext> {
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _revert = RevertGuard;
        let mut token = 0;
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::new(token)?;

        let mut level = 0i32;
        let mut returned = 0u32;
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenImpersonationLevel,
                (&mut level as *mut i32).cast(),
                size_of::<i32>() as u32,
                &mut returned,
            )
        } == 0
            || returned != size_of::<i32>() as u32
            || level < SecurityIdentification
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "anonymous pipe tokens are rejected",
            ));
        }

        let mut required = 0u32;
        unsafe {
            GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut required);
        }
        if required == 0 || required > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the caller token identity is invalid",
            ));
        }
        let mut identity = vec![0u8; required as usize];
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                identity.as_mut_ptr().cast(),
                identity.len() as u32,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let token_user = unsafe { identity.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
        if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the caller token SID is invalid",
            ));
        }
        let sid_length = unsafe { GetLengthSid(token_user.User.Sid) } as usize;
        let identity_start = identity.as_ptr() as usize;
        let identity_end = identity_start.saturating_add(identity.len());
        let sid_start = token_user.User.Sid as usize;
        let sid_end = sid_start.saturating_add(sid_length);
        if sid_length == 0
            || sid_length > 256
            || sid_start < identity_start
            || sid_end > identity_end
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the caller token SID is outside the token record",
            ));
        }
        let sid =
            unsafe { std::slice::from_raw_parts(token_user.User.Sid.cast::<u8>(), sid_length) }
                .to_vec();

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        returned = 0;
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut administrators_sid = [0u8; 68];
        let mut administrators_sid_length = administrators_sid.len() as u32;
        if unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                administrators_sid.as_mut_ptr().cast(),
                &mut administrators_sid_length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut administrator_member = 0;
        if unsafe {
            CheckTokenMembership(
                token.raw(),
                administrators_sid.as_mut_ptr().cast(),
                &mut administrator_member,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(CallerContext {
            sid,
            elevated_admin: administrator_member != 0 && elevation.TokenIsElevated != 0,
            component: TrustedClientComponent::Unknown,
        })
    }

    fn classify_installed_component(
        client: &Path,
        service: &Path,
        elevated_admin: bool,
    ) -> io::Result<TrustedClientComponent> {
        let canonical_client = fs::canonicalize(client)?;
        let canonical_service = fs::canonicalize(service)?;
        for path in [&canonical_client, &canonical_service] {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "component identity is not a regular file",
                ));
            }
        }

        let service_name = canonical_service
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if !service_name.eq_ignore_ascii_case("blackshard-service.exe")
            || canonical_client.parent() != canonical_service.parent()
        {
            return Ok(TrustedClientComponent::Unknown);
        }

        let component = match canonical_client
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
        {
            name if name.eq_ignore_ascii_case("blackshard-ui.exe") && elevated_admin => {
                TrustedClientComponent::ElevatedHelper
            }
            name if name.eq_ignore_ascii_case("blackshard-ui.exe") => {
                TrustedClientComponent::DesktopUi
            }
            name if name.eq_ignore_ascii_case("blackshard-service.exe") => {
                TrustedClientComponent::NotificationAgent
            }
            _ => TrustedClientComponent::Unknown,
        };
        if component == TrustedClientComponent::Unknown || unsigned_components_allowed() {
            return Ok(component);
        }

        if !crate::trust::verify_file(&canonical_service).is_trusted()
            || !crate::trust::verify_file(&canonical_client).is_trusted()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "production IPC components require valid Authenticode signatures",
            ));
        }
        Ok(component)
    }

    /// Whether the installer allowed unsigned components to use the control pipe.
    ///
    /// Preview builds ship unsigned, so the installer records that in the service's own registry
    /// key, which only administrators can write. The same-directory check above still applies,
    /// and the installation directory is writable by administrators alone.
    fn unsigned_components_allowed() -> bool {
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
        };

        let subkey: Vec<u16> = format!(
            r"SYSTEM\CurrentControlSet\Services\{}\Parameters",
            crate::service::SERVICE_NAME
        )
        .encode_utf16()
        .chain([0])
        .collect();
        let name: Vec<u16> = "AllowUnsignedComponents"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        status == 0 && value == 1
    }

    fn process_one_request(
        pipe: HANDLE,
        resources: &RpcServiceResources,
        caller: &CallerContext,
    ) -> Result<ResponseEnvelope, RpcFailure> {
        let bytes = read_frame(pipe, MAX_REQUEST_BYTES, IO_TIMEOUT)
            .map_err(|error| RpcFailure::transport(format!("could not read request: {error}")))?;
        let request: RequestEnvelope =
            serde_json::from_slice(&bytes).map_err(|error| RpcFailure {
                code: RpcErrorCode::InvalidRequest,
                message: format!("invalid request document: {error}"),
            })?;
        let request_id = request.request_id;
        let result = if request.version != IPC_PROTOCOL_VERSION {
            Err(RpcFailure {
                code: RpcErrorCode::InvalidRequest,
                message: format!(
                    "unsupported local protocol version {} (expected {})",
                    request.version, IPC_PROTOCOL_VERSION
                ),
            })
        } else {
            dispatch(request.command, resources, caller)
        };
        Ok(ResponseEnvelope {
            version: IPC_PROTOCOL_VERSION,
            request_id,
            result: match result {
                Ok(response) => RpcResult::Success { response },
                Err(error) => RpcResult::Error {
                    code: error.code,
                    message: truncate_message(error.message),
                },
            },
        })
    }

    fn process_one_amsi_request(
        pipe: HANDLE,
        resources: &RpcServiceResources,
        caller: &CallerContext,
    ) -> Result<AmsiResponseEnvelope, RpcFailure> {
        if caller.component != TrustedClientComponent::AmsiHost {
            return Err(RpcFailure {
                code: RpcErrorCode::AccessDenied,
                message: "only authenticated AMSI hosts may use this endpoint".to_owned(),
            });
        }
        let bytes = read_frame(pipe, MAX_AMSI_REQUEST_BYTES, AMSI_IO_TIMEOUT).map_err(|error| {
            RpcFailure::transport(format!("could not read AMSI request: {error}"))
        })?;
        let request: AmsiRequestEnvelope =
            serde_json::from_slice(&bytes).map_err(|error| RpcFailure {
                code: RpcErrorCode::InvalidRequest,
                message: format!("invalid AMSI request document: {error}"),
            })?;
        let request_id = request.request_id;
        let result = validate_and_scan_amsi(request, resources);
        Ok(AmsiResponseEnvelope {
            version: AMSI_IPC_PROTOCOL_VERSION,
            request_id,
            result: match result {
                Ok(verdict) => AmsiResult::Verdict { verdict },
                Err(error) => AmsiResult::Error {
                    code: error.code,
                    message: truncate_message(error.message),
                },
            },
        })
    }

    fn validate_and_scan_amsi(
        request: AmsiRequestEnvelope,
        resources: &RpcServiceResources,
    ) -> Result<DetectionVerdictView, RpcFailure> {
        if request.version != AMSI_IPC_PROTOCOL_VERSION {
            return Err(invalid(format!(
                "unsupported AMSI protocol version {} (expected {})",
                request.version, AMSI_IPC_PROTOCOL_VERSION
            )));
        }
        if !request.finalize {
            return Err(invalid("AMSI requests must explicitly finalize the scan"));
        }
        if request.chunks.len() > MAX_AMSI_CHUNKS
            || request
                .chunks
                .iter()
                .any(|chunk| chunk.len() > MAX_AMSI_CHUNK_BYTES)
        {
            return Err(invalid("AMSI content chunk bounds were exceeded"));
        }
        for value in [
            &request.application_name,
            &request.content_name,
            &request.content_type,
        ] {
            if value.chars().count() > MAX_WIRE_TEXT_CHARS {
                return Err(invalid("AMSI metadata is too long"));
            }
        }
        let total = request
            .chunks
            .iter()
            .try_fold(0usize, |total, chunk| total.checked_add(chunk.len()))
            .filter(|total| *total <= MAX_AMSI_CONTENT_BYTES)
            .ok_or_else(|| invalid("AMSI content exceeds the bounded scan limit"))?;
        let mut content = Vec::with_capacity(total);
        for chunk in request.chunks {
            content.extend_from_slice(&chunk);
        }
        let engine = resources
            .engine
            .read()
            .map_err(|_| internal("engine lock"))?
            .clone();
        let report = engine.scan_amsi_submission(&content);
        if report.verdict == crate::detection::DetectionVerdict::Malicious {
            // A script refused here never touches the minifilter, so this is the only record of it.
            let mut event = SecurityEvent::new(EventKind::Detection, "Script blocked by AMSI");
            let source = if request.content_name.is_empty() {
                &request.application_name
            } else {
                &request.content_name
            };
            event.path = Some(PathBuf::from(source));
            event.threat_name = report.threat_name.clone();
            event.risk_score = Some(report.risk_score);
            event.details = Some(format!(
                "block_reply_accepted=true; source=amsi; application={}",
                request.application_name
            ));
            let _ = resources.history.append(&event);
        }
        Ok(match report.verdict {
            crate::detection::DetectionVerdict::Clean => DetectionVerdictView::Clean,
            crate::detection::DetectionVerdict::Suspicious => DetectionVerdictView::Suspicious,
            crate::detection::DetectionVerdict::Malicious => DetectionVerdictView::Malicious,
            crate::detection::DetectionVerdict::Error => DetectionVerdictView::Error,
        })
    }

    fn dispatch(
        command: RpcCommand,
        resources: &RpcServiceResources,
        caller: &CallerContext,
    ) -> Result<RpcResponse, RpcFailure> {
        if !component_allows_command(caller.component, &command) {
            let message = format!(
                "{} is not authorized for component {:?}",
                command_name(&command),
                caller.component
            );
            append_rpc_access_denied(&resources.history, &message);
            return Err(RpcFailure {
                code: RpcErrorCode::AccessDenied,
                message,
            });
        }
        if requires_elevated_admin(&command) && !caller.elevated_admin {
            let command_name = command_name(&command);
            let message = format!("{command_name} requires an elevated administrator session");
            append_rpc_access_denied(&resources.history, &message);
            return Err(RpcFailure {
                code: RpcErrorCode::AccessDenied,
                message,
            });
        }
        match command {
            RpcCommand::Ping => Ok(RpcResponse::Pong),
            RpcCommand::GetSettings => {
                let settings = resources
                    .settings
                    .read()
                    .map_err(|_| internal("settings lock"))?;
                Ok(RpcResponse::Settings {
                    settings: settings.clone(),
                })
            }
            RpcCommand::SaveSettings { settings } => {
                settings
                    .save(&resources.settings_path)
                    .map_err(|error| RpcFailure {
                        code: RpcErrorCode::Internal,
                        message: format!("could not commit machine settings: {error}"),
                    })?;
                let validated =
                    Settings::load(&resources.settings_path).map_err(|error| RpcFailure {
                        code: RpcErrorCode::Internal,
                        message: format!("could not verify committed machine settings: {error}"),
                    })?;
                *resources
                    .settings
                    .write()
                    .map_err(|_| internal("settings lock"))? = validated;
                Ok(RpcResponse::Acknowledged {
                    message: "Settings saved by the protection service.".to_owned(),
                })
            }
            RpcCommand::StartScan { kind, roots } => {
                let scan_kind = validate_scan_kind(&kind, &roots)?;
                let mut slot = resources.scan.lock().map_err(|_| internal("scan lock"))?;
                if slot
                    .as_ref()
                    .is_some_and(|active| !active.job.snapshot().is_finished())
                {
                    return Err(RpcFailure {
                        code: RpcErrorCode::Busy,
                        message: "a system scan is already running".to_owned(),
                    });
                }
                if let Some(active) = slot.as_mut() {
                    active.job.join_if_finished();
                }
                let engine = resources
                    .engine
                    .read()
                    .map_err(|_| internal("detection engine lock"))?
                    .clone();
                let mut settings = resources
                    .settings
                    .read()
                    .map_err(|_| internal("settings lock"))?
                    .clone();
                if kind == ScanRequestKind::Turbo {
                    settings.low_resource_mode = false;
                    settings.worker_count = std::thread::available_parallelism()
                        .map(usize::from)
                        .unwrap_or(4)
                        .clamp(1, 16);
                }
                let job = ScanJob::start(
                    scan_kind,
                    engine,
                    Arc::clone(&resources.quarantine),
                    Arc::clone(&resources.history),
                    settings,
                );
                let progress =
                    ScanProgressView::from_with_requested_kind(&job.snapshot(), kind.clone());
                *slot = Some(ActiveScan {
                    job,
                    requested_kind: kind,
                    owner_sid: caller.sid.clone(),
                });
                Ok(RpcResponse::ScanProgress { progress })
            }
            RpcCommand::ScanStatus { scan_id } => {
                let mut slot = resources.scan.lock().map_err(|_| internal("scan lock"))?;
                let active = slot.as_mut().ok_or_else(|| RpcFailure {
                    code: RpcErrorCode::NotFound,
                    message: "no scan is available".to_owned(),
                })?;
                require_scan_owner(active, caller, resources)?;
                let snapshot = active.job.snapshot();
                if snapshot.id != scan_id {
                    return Err(RpcFailure {
                        code: RpcErrorCode::NotFound,
                        message: "the requested scan is no longer available".to_owned(),
                    });
                }
                active.job.join_if_finished();
                Ok(RpcResponse::ScanProgress {
                    progress: ScanProgressView::from_with_requested_kind(
                        &snapshot,
                        active.requested_kind.clone(),
                    ),
                })
            }
            RpcCommand::CancelScan { scan_id } => {
                let slot = resources.scan.lock().map_err(|_| internal("scan lock"))?;
                let active = slot.as_ref().ok_or_else(|| RpcFailure {
                    code: RpcErrorCode::NotFound,
                    message: "no scan is available".to_owned(),
                })?;
                require_scan_owner(active, caller, resources)?;
                let snapshot = active.job.snapshot();
                if snapshot.id != scan_id {
                    return Err(RpcFailure {
                        code: RpcErrorCode::NotFound,
                        message: "the requested scan is no longer available".to_owned(),
                    });
                }
                active.job.cancel();
                Ok(RpcResponse::Acknowledged {
                    message: "Scan cancellation requested.".to_owned(),
                })
            }
            RpcCommand::ListQuarantine => {
                let mut records = resources.quarantine.list().map_err(|error| RpcFailure {
                    code: RpcErrorCode::Internal,
                    message: format!("could not read quarantine: {error}"),
                })?;
                records.truncate(MAX_QUARANTINE_RESULTS);
                let records = records
                    .iter()
                    .map(|record| {
                        let mut view = QuarantineRecordView::from(record);
                        if !caller.elevated_admin {
                            view.original_path = record
                                .original_path
                                .file_name()
                                .map(|name| name.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "<protected path>".to_owned());
                        }
                        view
                    })
                    .collect();
                Ok(RpcResponse::Quarantine { records })
            }
            RpcCommand::RestoreQuarantine { id } => {
                let record = resources
                    .quarantine
                    .load(id)
                    .map_err(map_quarantine_error)?;
                let destination = resources
                    .quarantine
                    .restore(id, None, false)
                    .map_err(map_quarantine_error)?;
                // Restoring is the person overruling blackshard, so a shard this machine learned
                // for the file must not convict it again the moment it is opened.
                let _ = crate::shards::forget(&record.sha256);
                let mut event =
                    SecurityEvent::new(EventKind::Restored, "File restored from quarantine");
                event.path = Some(destination.clone());
                let _ = resources.history.append(&event);
                Ok(RpcResponse::Acknowledged {
                    message: format!("Restored to {}", destination.display()),
                })
            }
            RpcCommand::DeleteQuarantine { id } => {
                resources
                    .quarantine
                    .delete(id)
                    .map_err(map_quarantine_error)?;
                Ok(RpcResponse::Acknowledged {
                    message: "The quarantined copy was permanently removed.".to_owned(),
                })
            }
            RpcCommand::RecentActivity { limit } => {
                let events = resources
                    .history
                    .recent(limit.clamp(1, MAX_ACTIVITY_RESULTS))
                    .map_err(|error| RpcFailure {
                        code: RpcErrorCode::Internal,
                        message: format!("could not read activity history: {error}"),
                    })?
                    .into_iter()
                    .map(|event| sanitize_event(event, caller.elevated_admin))
                    .collect();
                Ok(RpcResponse::Activity { events })
            }
            RpcCommand::ClearActivity => {
                resources.history.clear().map_err(|error| RpcFailure {
                    code: RpcErrorCode::Internal,
                    message: format!("could not clear activity history: {error}"),
                })?;
                Ok(RpcResponse::Acknowledged {
                    message: "Activity history cleared.".to_owned(),
                })
            }
            RpcCommand::RequestUpdate => {
                if !resources.updates_configured {
                    return Err(RpcFailure {
                        code: RpcErrorCode::NotConfigured,
                        message: "this build has no authenticated update channel".to_owned(),
                    });
                }
                match resources.update_requests.try_send(()) {
                    Ok(()) | Err(TrySendError::Full(())) => Ok(RpcResponse::Acknowledged {
                        message: "Authenticated update check queued.".to_owned(),
                    }),
                    Err(TrySendError::Disconnected(())) => Err(RpcFailure {
                        code: RpcErrorCode::NotConfigured,
                        message: "the update controller is unavailable".to_owned(),
                    }),
                }
            }
            RpcCommand::RunSelfTest => match crate::self_test::run_self_test() {
                Ok(message) => Ok(RpcResponse::Acknowledged { message }),
                Err(error) => Err(RpcFailure {
                    code: RpcErrorCode::Internal,
                    message: error,
                }),
            },
            RpcCommand::CheckForUpdates => Ok(RpcResponse::Acknowledged {
                message: "Update check queued.".to_owned(),
            }),
            RpcCommand::GetFreshClamStatus => {
                let data_root = std::env::var_os("PROGRAMDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                    .join("blackshard");
                let active =
                    crate::clamdb::downloader::active_database(&data_root).map_err(|error| {
                        RpcFailure {
                            code: RpcErrorCode::NotConfigured,
                            message: format!(
                                "no authenticated FreshClam database is active: {error}"
                            ),
                        }
                    })?;
                let age = chrono::Utc::now()
                    .signed_duration_since(active.activated_at)
                    .num_hours()
                    .max(0) as u64;
                Ok(RpcResponse::FreshClamStatus {
                    status: FreshClamStatusView {
                        // The definitions are now evaluated by blackshard's own engine, so the
                        // reported engine version is blackshard's rather than a sidecar's.
                        engine_version: format!("blackshard {}", env!("CARGO_PKG_VERSION")),
                        database_version: active.version,
                        database_age_hours: age,
                    },
                })
            }
        }
    }

    fn validate_scan_kind(
        kind: &ScanRequestKind,
        roots: &[String],
    ) -> Result<ScanKind, RpcFailure> {
        match kind {
            ScanRequestKind::Quick | ScanRequestKind::Turbo => {
                // The client names the folders in its own profile; the service adds the image of
                // every running process, which only it can see across sessions. Malware that is
                // already running is the first thing a quick scan should find.
                let mut paths = validate_scan_roots(roots, "quick")?;
                paths.extend(crate::realtime::running_process_images());
                Ok(ScanKind::Custom(paths))
            }
            ScanRequestKind::Full if roots.is_empty() => Ok(ScanKind::Full),
            ScanRequestKind::Full => Err(invalid("a full scan does not accept client roots")),
            ScanRequestKind::Custom {
                roots: requested_roots,
            } => {
                if requested_roots != roots {
                    return Err(invalid("custom scan roots did not match the request scope"));
                }
                Ok(ScanKind::Custom(validate_scan_roots(roots, "custom")?))
            }
        }
    }

    fn validate_scan_roots(roots: &[String], label: &str) -> Result<Vec<PathBuf>, RpcFailure> {
        if roots.is_empty() || roots.len() > MAX_CUSTOM_SCAN_ROOTS {
            return Err(invalid(format!("a {label} scan requires 1 to 16 roots")));
        }
        let mut paths = Vec::with_capacity(roots.len());
        for root in roots {
            if root.is_empty() || root.encode_utf16().count() > 32_767 {
                return Err(invalid(format!(
                    "a {label} scan path has an invalid length"
                )));
            }
            let path = PathBuf::from(root);
            if !path.is_absolute() || !path.exists() {
                return Err(invalid(format!(
                    "{label} scan root is not an existing absolute path: {root}"
                )));
            }
            paths.push(path);
        }
        Ok(paths)
    }

    fn require_scan_owner(
        active: &ActiveScan,
        caller: &CallerContext,
        resources: &RpcServiceResources,
    ) -> Result<(), RpcFailure> {
        if active.owner_sid == caller.sid || caller.elevated_admin {
            return Ok(());
        }
        let message =
            "a scan can only be inspected or cancelled by its owner or an elevated administrator";
        append_rpc_access_denied(&resources.history, message);
        Err(RpcFailure {
            code: RpcErrorCode::AccessDenied,
            message: message.to_owned(),
        })
    }

    fn command_name(command: &RpcCommand) -> &'static str {
        match command {
            RpcCommand::Ping => "ping",
            RpcCommand::GetSettings => "read settings",
            RpcCommand::SaveSettings { .. } => "changing machine protection settings",
            RpcCommand::StartScan { .. } => "starting a scan",
            RpcCommand::ScanStatus { .. } => "reading scan status",
            RpcCommand::CancelScan { .. } => "cancelling a scan",
            RpcCommand::ListQuarantine => "reading machine quarantine",
            RpcCommand::RestoreQuarantine { .. } => "restoring a quarantined file",
            RpcCommand::DeleteQuarantine { .. } => "deleting a quarantined file",
            RpcCommand::RecentActivity { .. } => "reading machine activity",
            RpcCommand::ClearActivity => "clearing machine activity",
            RpcCommand::RequestUpdate => "requesting an update",
            RpcCommand::RunSelfTest => "running protection self-test",
            RpcCommand::CheckForUpdates => "checking for freshclam updates",
            RpcCommand::GetFreshClamStatus => "getting freshclam status",
        }
    }

    fn sanitize_event(mut event: SecurityEvent, include_sensitive_paths: bool) -> SecurityEvent {
        event.summary = bounded_string(event.summary, 256);
        event.path = event.path.map(|path| {
            if include_sensitive_paths {
                PathBuf::from(bounded_string(path.to_string_lossy(), MAX_WIRE_PATH_CHARS))
            } else {
                path.file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("<protected path>"))
            }
        });
        event.threat_name = event.threat_name.map(|value| bounded_string(value, 128));
        event.details = include_sensitive_paths
            .then(|| {
                event
                    .details
                    .map(|value| bounded_string(value, MAX_WIRE_TEXT_CHARS))
            })
            .flatten();
        event
    }

    fn map_quarantine_error(error: io::Error) -> RpcFailure {
        RpcFailure {
            code: if error.kind() == io::ErrorKind::NotFound {
                RpcErrorCode::NotFound
            } else {
                RpcErrorCode::Internal
            },
            message: error.to_string(),
        }
    }

    fn invalid(message: impl Into<String>) -> RpcFailure {
        RpcFailure {
            code: RpcErrorCode::InvalidRequest,
            message: message.into(),
        }
    }

    fn internal(name: &str) -> RpcFailure {
        RpcFailure {
            code: RpcErrorCode::Internal,
            message: format!("{name} was poisoned"),
        }
    }

    fn append_rpc_error(history: &EventHistory, message: &str) {
        let mut event = SecurityEvent::new(EventKind::Error, "Local control channel error");
        event.details = Some(truncate_message(message.to_owned()));
        let _ = history.append(&event);
    }

    fn append_rpc_access_denied(history: &EventHistory, message: &str) {
        let mut event = SecurityEvent::new(EventKind::Error, "Local control action denied");
        event.details = Some(bounded_string(message, MAX_WIRE_TEXT_CHARS));
        let _ = history.append(&event);
    }

    #[derive(Debug, Clone, Default)]
    pub struct IpcClient;

    impl IpcClient {
        fn call(&self, command: RpcCommand) -> Result<RpcResponse, RpcFailure> {
            call_endpoint(command, PIPE_NAME, MAX_REQUEST_BYTES)
        }

        pub fn get_settings(&self) -> Result<Settings, RpcFailure> {
            match self.call(RpcCommand::GetSettings)? {
                RpcResponse::Settings { settings } => Ok(settings),
                _ => Err(unexpected()),
            }
        }

        pub fn save_settings(&self, settings: Settings) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::SaveSettings { settings })?)
        }

        pub fn list_quarantine(&self) -> Result<Vec<QuarantineRecordView>, RpcFailure> {
            match self.call(RpcCommand::ListQuarantine)? {
                RpcResponse::Quarantine { records } => Ok(records),
                _ => Err(unexpected()),
            }
        }

        pub fn restore_quarantine(&self, id: Uuid) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::RestoreQuarantine { id })?)
        }

        pub fn delete_quarantine(&self, id: Uuid) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::DeleteQuarantine { id })?)
        }

        pub fn recent_activity(&self, limit: usize) -> Result<Vec<SecurityEvent>, RpcFailure> {
            match self.call(RpcCommand::RecentActivity { limit })? {
                RpcResponse::Activity { events } => Ok(events),
                _ => Err(unexpected()),
            }
        }

        pub fn clear_activity(&self) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::ClearActivity)?)
        }

        pub fn request_update(&self) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::RequestUpdate)?)
        }

        fn start_scan(&self, kind: ScanRequestKind) -> Result<ScanProgressView, RpcFailure> {
            let roots = match &kind {
                ScanRequestKind::Quick | ScanRequestKind::Turbo => quick_scan_roots(),
                ScanRequestKind::Full => Vec::new(),
                ScanRequestKind::Custom { roots } => roots.clone(),
            };
            scan_progress(self.call(RpcCommand::StartScan { kind, roots })?)
        }

        fn scan_status(&self, scan_id: Uuid) -> Result<ScanProgressView, RpcFailure> {
            scan_progress(self.call(RpcCommand::ScanStatus { scan_id })?)
        }

        pub fn cancel_scan(&self, scan_id: Uuid) -> Result<String, RpcFailure> {
            acknowledged(self.call(RpcCommand::CancelScan { scan_id })?)
        }

        pub fn get_freshclam_status(&self) -> Result<FreshClamStatusView, RpcFailure> {
            match self.call(RpcCommand::GetFreshClamStatus)? {
                RpcResponse::FreshClamStatus { status } => Ok(status),
                _ => Err(invalid("unexpected response to get_freshclam_status")),
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct AmsiIpcClient;

    impl AmsiIpcClient {
        pub fn scan(
            &self,
            app_name: String,
            content_name: String,
            content: Vec<u8>,
        ) -> Result<DetectionVerdictView, RpcFailure> {
            if content.len() > MAX_AMSI_CONTENT_BYTES {
                return Err(invalid("AMSI content exceeds the bounded scan limit"));
            }
            let request_id = Uuid::new_v4();
            let request = AmsiRequestEnvelope {
                version: AMSI_IPC_PROTOCOL_VERSION,
                request_id,
                session_id: Uuid::new_v4(),
                application_name: app_name,
                content_name,
                content_type: "application/octet-stream".to_owned(),
                chunks: content
                    .chunks(MAX_AMSI_CHUNK_BYTES)
                    .map(<[u8]>::to_vec)
                    .collect(),
                finalize: true,
            };
            let pipe = connect_client(AMSI_PIPE_NAME).map_err(|error| {
                RpcFailure::transport(format!("AMSI scan service is unavailable: {error}"))
            })?;
            write_json_frame(pipe.raw(), &request, MAX_AMSI_REQUEST_BYTES).map_err(|error| {
                RpcFailure::transport(format!("could not send AMSI scan request: {error}"))
            })?;
            let bytes =
                read_frame(pipe.raw(), MAX_RESPONSE_BYTES, IO_TIMEOUT).map_err(|error| {
                    RpcFailure::transport(format!("could not read AMSI scan response: {error}"))
                })?;
            let response: AmsiResponseEnvelope =
                serde_json::from_slice(&bytes).map_err(|error| RpcFailure {
                    code: RpcErrorCode::Internal,
                    message: format!("invalid AMSI service response: {error}"),
                })?;
            if response.version != AMSI_IPC_PROTOCOL_VERSION || response.request_id != request_id {
                return Err(RpcFailure::transport(
                    "the AMSI service response did not match this request",
                ));
            }
            match response.result {
                AmsiResult::Verdict { verdict } => Ok(verdict),
                AmsiResult::Error { code, message } => Err(RpcFailure { code, message }),
            }
        }
    }

    fn call_endpoint(
        command: RpcCommand,
        pipe_name: &str,
        max_request_bytes: usize,
    ) -> Result<RpcResponse, RpcFailure> {
        let request_id = Uuid::new_v4();
        let request = RequestEnvelope {
            version: IPC_PROTOCOL_VERSION,
            request_id,
            command,
        };
        let pipe = connect_client(pipe_name)
            .map_err(|error| RpcFailure::transport(format!("{SERVICE_UNAVAILABLE}: {error}")))?;
        write_json_frame(pipe.raw(), &request, max_request_bytes).map_err(|error| {
            RpcFailure::transport(format!("could not send service request: {error}"))
        })?;
        let bytes = read_frame(pipe.raw(), MAX_RESPONSE_BYTES, IO_TIMEOUT).map_err(|error| {
            RpcFailure::transport(format!("could not read service response: {error}"))
        })?;
        let response: ResponseEnvelope =
            serde_json::from_slice(&bytes).map_err(|error| RpcFailure {
                code: RpcErrorCode::Internal,
                message: format!("invalid service response: {error}"),
            })?;
        if response.version != IPC_PROTOCOL_VERSION || response.request_id != request_id {
            return Err(RpcFailure::transport(
                "the service response did not match this request",
            ));
        }
        match response.result {
            RpcResult::Success { response } => Ok(response),
            RpcResult::Error { code, message } => Err(RpcFailure { code, message }),
        }
    }

    fn connect_client(pipe_name: &str) -> io::Result<OwnedHandle> {
        let name = wide(pipe_name);
        let deadline = Instant::now() + Duration::from_millis(PIPE_DEFAULT_TIMEOUT_MS as u64);
        loop {
            if unsafe { WaitNamedPipeW(name.as_ptr(), 500) } != 0 {
                let handle = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        CLIENT_PIPE_ACCESS,
                        0,
                        null(),
                        OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        0,
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    let handle = OwnedHandle::new(handle)?;
                    // Nothing is written until the pipe has been shown to belong to the service.
                    verify_pipe_owner(handle.raw())?;
                    return Ok(handle);
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(231) {
                    return Err(err);
                }
            } else {
                let err = io::Error::last_os_error();
                // 2: no instance exists yet. 121: every instance stayed busy for the 500 ms wait.
                // Both are worth retrying until the overall deadline; giving up on the first busy
                // wait turned one slow client into a failed, and therefore unscanned, request.
                if !matches!(err.raw_os_error(), Some(2) | Some(121)) {
                    return Err(err);
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::last_os_error());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Opens and immediately closes a connection, releasing a listener parked in
    /// `ConnectNamedPipe`. Nothing is sent, so the server needs no verification, and one attempt
    /// is enough because `stop_workers` repeats it.
    fn poke_listener(pipe_name: &str) {
        let name = wide(pipe_name);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_PIPE_ACCESS,
                0,
                null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(handle);
            }
        }
    }

    fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
        let mut sid = vec![0u8; 68];
        let mut length = sid.len() as u32;
        if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        sid.truncate(length as usize);
        Ok(sid)
    }

    /// Owners a genuine blackshard pipe can have.
    ///
    /// The service runs as SYSTEM, and objects it creates are owned by SYSTEM or, under the
    /// default "objects created by administrators" policy, by the Administrators group. A standard
    /// user cannot make either the owner of a pipe they create.
    fn trusted_pipe_owners() -> io::Result<Vec<Vec<u8>>> {
        #[allow(unused_mut)]
        let mut owners = vec![
            well_known_sid(WinLocalSystemSid)?,
            well_known_sid(WinBuiltinAdministratorsSid)?,
        ];
        // Test builds serve the pipes from the unelevated test process, which then owns them.
        // This exists only in `cargo test` binaries and is never compiled into a release.
        #[cfg(test)]
        owners.push(transport_tests::current_process_owner_sid()?);
        Ok(owners)
    }

    fn is_trusted_owner(owner: *mut c_void, trusted: &[Vec<u8>]) -> bool {
        !owner.is_null()
            && trusted
                .iter()
                .any(|sid| unsafe { EqualSid(owner, sid.as_ptr() as *mut c_void) } != 0)
    }

    /// Refuses a pipe that was not created by privileged code.
    ///
    /// Every instance of a named pipe shares one security descriptor, set by whoever created the
    /// first. A squatter that claims the name first therefore owns the whole pipe, and this check
    /// rejects it. It only holds because the DACLs above deny non-admins
    /// `FILE_CREATE_PIPE_INSTANCE`; otherwise a rogue instance could join a genuine pipe and
    /// inherit its trusted owner.
    ///
    /// The owner is read from the client's own handle, so no access to the server process is
    /// needed. That matters: a standard user cannot open a SYSTEM service's process, which rules
    /// out checking the server's image path from inside the AMSI provider.
    fn verify_pipe_owner(pipe: HANDLE) -> io::Result<()> {
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = SecurityDescriptor(descriptor);
        if is_trusted_owner(owner, &trusted_pipe_owners()?) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the pipe is not owned by SYSTEM or Administrators; refusing a possible impostor",
            ))
        }
    }

    fn quick_scan_roots() -> Vec<String> {
        let mut roots = Vec::<PathBuf>::new();
        // Where malware lands and installs itself: the user's own folders, roaming AppData (which
        // holds the Startup folder), per-user program installs, and the shared Public profile.
        if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            roots.push(profile.join("Desktop"));
            roots.push(profile.join("Downloads"));
            roots.push(profile.join("Documents"));
            roots.push(profile.join(r"AppData\Roaming"));
            roots.push(profile.join(r"AppData\Local\Programs"));
        }
        if let Some(public) = std::env::var_os("PUBLIC").map(PathBuf::from) {
            roots.push(public);
        }
        if let Some(temp) = std::env::var_os("TEMP").map(PathBuf::from) {
            roots.push(temp);
        }
        if let Some(program_data) = std::env::var_os("PROGRAMDATA").map(PathBuf::from) {
            roots.push(program_data.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
        }
        roots.retain(|path| path.is_absolute() && path.exists());
        roots.sort_by_key(|path| path.to_string_lossy().to_lowercase());
        roots.dedup_by(|left, right| {
            left.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
        });
        roots
            .into_iter()
            .take(MAX_CUSTOM_SCAN_ROOTS)
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    pub struct ServiceScanJob {
        client: IpcClient,
        scan_id: Uuid,
        snapshot: Arc<Mutex<ScanProgressView>>,
        stop_polling: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl ServiceScanJob {
        pub fn start(client: IpcClient, kind: ScanRequestKind) -> Result<Self, RpcFailure> {
            let initial = client.start_scan(kind)?;
            let scan_id = initial.id;
            let snapshot = Arc::new(Mutex::new(initial));
            let stop_polling = Arc::new(AtomicBool::new(false));
            let worker_snapshot = Arc::clone(&snapshot);
            let worker_stop = Arc::clone(&stop_polling);
            let worker_client = client.clone();
            let worker = thread::Builder::new()
                .name("blackshard-scan-status".to_owned())
                .spawn(move || {
                    let mut consecutive_failures = 0u8;
                    while !worker_stop.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(250));
                        match worker_client.scan_status(scan_id) {
                            Ok(progress) => {
                                let finished = progress.is_finished();
                                if let Ok(mut current) = worker_snapshot.lock() {
                                    *current = progress;
                                }
                                consecutive_failures = 0;
                                if finished {
                                    break;
                                }
                            }
                            Err(error) => {
                                consecutive_failures = consecutive_failures.saturating_add(1);
                                if consecutive_failures >= 3 {
                                    if let Ok(mut current) = worker_snapshot.lock() {
                                        current.phase = ScanPhaseView::Failed;
                                        current.finished_at = Some(Utc::now());
                                        current.failure = Some(error.to_string());
                                    }
                                    break;
                                }
                            }
                        }
                    }
                })
                .map_err(|error| {
                    RpcFailure::transport(format!("could not start scan status monitor: {error}"))
                })?;
            Ok(Self {
                client,
                scan_id,
                snapshot,
                stop_polling,
                worker: Some(worker),
            })
        }

        pub fn snapshot(&self) -> ScanProgressView {
            self.snapshot
                .lock()
                .expect("scan progress lock was poisoned")
                .clone()
        }

        pub fn cancel(&self) {
            let _ = self.client.cancel_scan(self.scan_id);
            if let Ok(mut progress) = self.snapshot.lock() {
                if !progress.is_finished() {
                    progress.phase = ScanPhaseView::Cancelling;
                }
            }
        }

        pub fn join_if_finished(&mut self) {
            if self.snapshot().is_finished() {
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
        }
    }

    impl Drop for ServiceScanJob {
        fn drop(&mut self) {
            self.stop_polling.store(true, Ordering::Release);
        }
    }

    fn scan_progress(response: RpcResponse) -> Result<ScanProgressView, RpcFailure> {
        match response {
            RpcResponse::ScanProgress { progress } => Ok(progress),
            _ => Err(unexpected()),
        }
    }

    fn acknowledged(response: RpcResponse) -> Result<String, RpcFailure> {
        match response {
            RpcResponse::Acknowledged { message } => Ok(message),
            _ => Err(unexpected()),
        }
    }

    fn unexpected() -> RpcFailure {
        RpcFailure::transport("the protection service returned an unexpected response")
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn write_json_frame<T: Serialize>(handle: HANDLE, value: &T, maximum: usize) -> io::Result<()> {
        let body = serde_json::to_vec(value).map_err(io::Error::other)?;
        if body.is_empty() || body.len() > maximum || body.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local control payload exceeds its size limit",
            ));
        }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        write_all(handle, &frame)
    }

    fn read_frame(handle: HANDLE, maximum: usize, timeout: Duration) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut length = [0u8; 4];
        read_exact_until(handle, &mut length, deadline)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local control frame has an invalid size",
            ));
        }
        let mut body = vec![0u8; length];
        read_exact_until(handle, &mut body, deadline)?;
        Ok(body)
    }

    fn read_exact_until(handle: HANDLE, output: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut offset = 0usize;
        while offset < output.len() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local control read timed out",
                ));
            }
            let mut available = 0u32;
            if unsafe {
                PeekNamedPipe(
                    handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "local control peer disconnected",
                    ));
                }
                return Err(error);
            }
            if available == 0 {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            let amount = (output.len() - offset).min(available as usize);
            let mut read = 0u32;
            if unsafe {
                ReadFile(
                    handle,
                    output[offset..].as_mut_ptr(),
                    amount as u32,
                    &mut read,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "local control peer disconnected",
                ));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn write_all(handle: HANDLE, bytes: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut offset = 0usize;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local control write timed out",
                ));
            }
            let amount = (bytes.len() - offset).min(32 * 1024);
            let mut written = 0u32;
            if unsafe {
                WriteFile(
                    handle,
                    bytes[offset..].as_ptr(),
                    amount as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                return Err(error);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "local control write returned zero bytes",
                ));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn truncate_message(mut message: String) -> String {
        const MAX_MESSAGE_CHARS: usize = 2_048;
        if message.chars().count() > MAX_MESSAGE_CHARS {
            message = message.chars().take(MAX_MESSAGE_CHARS).collect();
            message.push_str("...");
        }
        message
    }

    #[cfg(test)]
    mod transport_tests {
        use super::*;
        use crate::detection::DetectionEngine;
        use crate::realtime::new_shared_detection_engine;
        use std::sync::Barrier;

        /// Starts a real server on the machine-wide pipe names, or returns `None` when an
        /// installed service already owns them.
        fn start_test_server(root: &Path) -> Option<RpcServer> {
            let (update_sender, _update_receiver) = std::sync::mpsc::sync_channel(1);
            let resources = RpcServiceResources::new(
                new_shared_detection_engine(DetectionEngine::builtin().unwrap()),
                Arc::new(QuarantineStore::new(root.join("vault"))),
                Arc::new(EventHistory::new(root.join("history.jsonl"))),
                Arc::new(RwLock::new(Settings::default())),
                root.join("settings.json"),
                update_sender,
                false,
            );
            match RpcServer::start(resources) {
                Ok(server) => Some(server),
                Err(error) => {
                    eprintln!("skipping: the blackshard pipes are already served here ({error})");
                    None
                }
            }
        }

        /// The owner that objects created by this process receive, which is what owns the pipes
        /// a test server creates.
        pub(super) fn current_process_owner_sid() -> io::Result<Vec<u8>> {
            use windows_sys::Win32::Security::{TokenOwner, TOKEN_OWNER};
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut token = 0;
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = OwnedHandle::new(token)?;
            let mut buffer = vec![0u8; 256];
            let mut returned = 0u32;
            if unsafe {
                GetTokenInformation(
                    token.raw(),
                    TokenOwner,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let owner = unsafe { buffer.as_ptr().cast::<TOKEN_OWNER>().read_unaligned() }.Owner;
            let length = unsafe { GetLengthSid(owner) } as usize;
            Ok(unsafe { std::slice::from_raw_parts(owner as *const u8, length) }.to_vec())
        }

        #[test]
        fn non_admin_callers_cannot_create_pipe_instances() {
            const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0004;
            assert_eq!(CLIENT_PIPE_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
            for (sddl, principal) in [(AMSI_SDDL, "AU"), (MANAGEMENT_SDDL, "IU")] {
                let ace = sddl
                    .split('(')
                    .find(|ace| ace.ends_with(&format!(";;;{principal})")))
                    .unwrap_or_else(|| panic!("{sddl} grants {principal} nothing"));
                // Symbolic generic rights are exactly what must not come back.
                assert!(!ace.contains("GW") && !ace.contains("GA"), "{sddl}");
                assert!(ace.contains(&format!("{CLIENT_PIPE_ACCESS:#x}")), "{sddl}");
            }
        }

        #[test]
        fn only_privileged_owners_are_trusted() {
            use windows_sys::Win32::Security::{WinBuiltinUsersSid, WinWorldSid};

            let production = [
                well_known_sid(WinLocalSystemSid).unwrap(),
                well_known_sid(WinBuiltinAdministratorsSid).unwrap(),
            ];
            let as_owner = |sid: &Vec<u8>| sid.as_ptr() as *mut c_void;

            assert!(is_trusted_owner(as_owner(&production[0]), &production));
            assert!(is_trusted_owner(as_owner(&production[1]), &production));
            // A pipe created by an ordinary user is owned by that user or a group like these.
            for squatter in [WinWorldSid, WinBuiltinUsersSid] {
                let sid = well_known_sid(squatter).unwrap();
                assert!(!is_trusted_owner(as_owner(&sid), &production));
            }
            assert!(!is_trusted_owner(null_mut(), &production));
        }

        /// One test owns the pipes so parallel tests never race for the same machine-wide names.
        #[test]
        fn concurrent_amsi_clients_are_all_scanned() {
            let temporary = tempfile::tempdir().unwrap();
            let Some(server) = start_test_server(temporary.path()) else {
                return;
            };

            // Sized to pass comfortably on a small CI runner. The idle-client check below is what
            // discriminates the old single-instance server; this is a correctness check under load.
            const CLIENTS: usize = 64;
            let barrier = Arc::new(Barrier::new(CLIENTS));
            let started = Instant::now();
            let workers: Vec<_> = (0..CLIENTS)
                .map(|index| {
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        let content = if index == 0 {
                            crate::self_test::PAYLOAD.to_vec()
                        } else {
                            format!("Write-Host 'client {index}'").into_bytes()
                        };
                        let begun = Instant::now();
                        let result = AmsiIpcClient.scan(
                            "blackshard-test".to_owned(),
                            format!("client-{index}.ps1"),
                            content,
                        );
                        (index, result, begun.elapsed())
                    })
                })
                .collect();

            let mut failures = Vec::new();
            let mut slowest = Duration::ZERO;
            for worker in workers {
                let (index, result, elapsed) = worker.join().unwrap();
                slowest = slowest.max(elapsed);
                match result {
                    Ok(verdict) if index == 0 => {
                        assert_eq!(verdict, DetectionVerdictView::Malicious)
                    }
                    Ok(_) => {}
                    Err(error) => failures.push(format!("client {index}: {}", error.message)),
                }
            }
            eprintln!(
                "{CLIENTS} concurrent AMSI clients: {} failed, slowest {:?}, wall {:?}",
                failures.len(),
                slowest,
                started.elapsed()
            );
            // A client that connects and never writes used to hold the only instance until its
            // read timed out, and every other script on the machine waited behind it.
            let idle = connect_client(AMSI_PIPE_NAME).unwrap();
            let begun = Instant::now();
            let behind_idle = AmsiIpcClient.scan(
                "blackshard-test".to_owned(),
                "behind-idle.ps1".to_owned(),
                b"Write-Host 'waiting'".to_vec(),
            );
            let waited = begun.elapsed();
            drop(idle);
            eprintln!("scan behind an idle client took {waited:?}");

            server.stop();

            // Every failure here is a script the AMSI provider would have waved through as clean.
            assert!(failures.is_empty(), "{failures:#?}");
            assert!(behind_idle.is_ok(), "{:?}", behind_idle.err());
            // The old server failed this outright (`is_ok` above). The bound is only there to catch
            // a scan that technically succeeds after waiting out the idle client's timeout.
            assert!(
                waited < AMSI_IO_TIMEOUT * 4,
                "blocked behind an idle client: {waited:?}"
            );
        }
    }
}

#[cfg(windows)]
pub use windows_transport::{
    AmsiIpcClient, IpcClient, RpcServer, RpcServiceResources, ServiceScanJob,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_documents_are_versioned_and_reject_unknown_fields() {
        let request = RequestEnvelope {
            version: IPC_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            command: RpcCommand::RecentActivity { limit: 25 },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: RequestEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.version, IPC_PROTOCOL_VERSION);

        let invalid = format!(
            r#"{{"version":1,"request_id":"{}","command":{{"command":"ping"}},"extra":true}}"#,
            Uuid::new_v4()
        );
        assert!(serde_json::from_str::<RequestEnvelope>(&invalid).is_err());
    }

    #[test]
    fn amsi_protocol_is_structurally_separate_from_management_commands() {
        let management = RequestEnvelope {
            version: IPC_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            command: RpcCommand::SaveSettings {
                settings: Settings::default(),
            },
        };
        let encoded = serde_json::to_vec(&management).unwrap();
        assert!(serde_json::from_slice::<AmsiRequestEnvelope>(&encoded).is_err());

        let amsi = AmsiRequestEnvelope {
            version: AMSI_IPC_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            application_name: "PowerShell".to_owned(),
            content_name: "script.ps1".to_owned(),
            content_type: "text/powershell".to_owned(),
            chunks: vec![b"Write-Output 'safe'".to_vec()],
            finalize: true,
        };
        let encoded = serde_json::to_vec(&amsi).unwrap();
        assert!(serde_json::from_slice::<RequestEnvelope>(&encoded).is_err());
    }

    #[test]
    fn quarantine_wire_view_never_contains_neutralization_material() {
        let json = serde_json::to_string(&QuarantineRecordView {
            id: Uuid::nil(),
            original_path: r"C:\sample.exe".to_owned(),
            quarantined_at: Utc::now(),
            sha256: "00".repeat(32),
            size: 10,
            threat_name: "Unit.Test".to_owned(),
            risk_score: 100,
            state: IsolationState::Isolated,
        })
        .unwrap();
        assert!(!json.contains("key"));
        assert!(!json.contains("nonce"));
    }

    #[test]
    fn scan_phase_terminal_states_are_explicit() {
        assert!(ScanPhaseView::Completed.is_finished());
        assert!(ScanPhaseView::Cancelled.is_finished());
        assert!(ScanPhaseView::Failed.is_finished());
        assert!(!ScanPhaseView::Scanning.is_finished());
    }

    #[test]
    fn machine_wide_sensitive_actions_require_elevated_administration() {
        assert!(requires_elevated_admin(&RpcCommand::SaveSettings {
            settings: Settings::default(),
        }));
        assert!(!requires_elevated_admin(&RpcCommand::ListQuarantine));
        assert!(requires_elevated_admin(&RpcCommand::RestoreQuarantine {
            id: Uuid::nil(),
        }));
        assert!(requires_elevated_admin(&RpcCommand::DeleteQuarantine {
            id: Uuid::nil(),
        }));
        assert!(!requires_elevated_admin(&RpcCommand::RecentActivity {
            limit: 10,
        }));
        assert!(requires_elevated_admin(&RpcCommand::ClearActivity));
        assert!(!requires_elevated_admin(&RpcCommand::StartScan {
            kind: ScanRequestKind::Quick,
            roots: vec![r"C:\Users\Example\Downloads".to_owned()],
        }));
        assert!(!requires_elevated_admin(&RpcCommand::RequestUpdate));
    }

    #[test]
    fn component_command_matrix_separates_ui_notification_and_amsi_authority() {
        let read_activity = RpcCommand::RecentActivity { limit: 10 };
        let save = RpcCommand::SaveSettings {
            settings: Settings::default(),
        };

        assert!(component_allows_command(
            TrustedClientComponent::DesktopUi,
            &read_activity
        ));
        assert!(!component_allows_command(
            TrustedClientComponent::DesktopUi,
            &save
        ));
        assert!(component_allows_command(
            TrustedClientComponent::ElevatedHelper,
            &save
        ));
        assert!(component_allows_command(
            TrustedClientComponent::NotificationAgent,
            &read_activity
        ));
        assert!(!component_allows_command(
            TrustedClientComponent::NotificationAgent,
            &RpcCommand::StartScan {
                kind: ScanRequestKind::Full,
                roots: Vec::new(),
            }
        ));
        assert!(!component_allows_command(
            TrustedClientComponent::AmsiHost,
            &RpcCommand::Ping
        ));
        assert!(!component_allows_command(
            TrustedClientComponent::Unknown,
            &RpcCommand::Ping
        ));
    }
}
