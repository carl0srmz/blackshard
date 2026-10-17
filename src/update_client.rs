use crate::definitions::{
    DefinitionPayload, DefinitionSource, DefinitionStore, MAX_DEFINITION_PAYLOAD_BYTES,
};
use crate::updater::{
    verify_manifest, verify_update, ActiveUpdate, SignedUpdateEnvelope, UpdateError,
    UpdateManifest, UpdateScheduler, MAX_ENVELOPE_BYTES,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use rand::Rng;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use url::Url;

const MAX_URL_BYTES: usize = 2_048;
const EVENT_CHANNEL_CAPACITY: usize = 32;
const CONTROL_CHANNEL_CAPACITY: usize = 1;
const HTTP_READ_CHUNK_BYTES: usize = 64 * 1024;
const MIN_OPERATION_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_OVERALL_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OVERALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    pub resolve: Duration,
    pub connect: Duration,
    pub send: Duration,
    pub receive: Duration,

    pub overall: Duration,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            resolve: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            send: Duration::from_secs(10),
            receive: Duration::from_secs(20),
            overall: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdateClientConfig {
    pub manifest_url: String,

    pub allowed_payload_origins: Vec<String>,
    pub maximum_envelope_bytes: usize,
    pub maximum_payload_bytes: u64,
    pub timeouts: HttpTimeouts,
    pub scheduler: UpdateScheduler,
    pub check_on_start: bool,
    pub user_agent: String,
}

impl UpdateClientConfig {
    pub fn new(manifest_url: impl Into<String>) -> Self {
        Self {
            manifest_url: manifest_url.into(),
            allowed_payload_origins: Vec::new(),
            maximum_envelope_bytes: MAX_ENVELOPE_BYTES,
            maximum_payload_bytes: MAX_DEFINITION_PAYLOAD_BYTES as u64,
            timeouts: HttpTimeouts::default(),
            scheduler: UpdateScheduler::default(),
            check_on_start: true,
            user_agent: format!("blackshard/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn from_embedded_endpoint(manifest_url: &'static str) -> Result<Self, UpdateClientError> {
        let config = Self::new(manifest_url);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), UpdateClientError> {
        ValidatedConfig::try_from(self).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateTrigger {
    Startup,
    Scheduled,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatePhase {
    Starting,
    Sleeping,
    DownloadingManifest,
    AuthenticatingManifest,
    DownloadingPayload,
    ValidatingPayload,
    Activating,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateResultStatus {
    NeverChecked,
    Current { sequence: u64 },
    Installed { sequence: u64, version: String },
    Failed { message: String },
}

#[derive(Debug, Clone)]
pub struct UpdateStatus {
    pub phase: UpdatePhase,
    pub last_attempt: Option<SystemTime>,
    pub last_successful_check: Option<SystemTime>,
    pub next_check: Option<SystemTime>,
    pub result: UpdateResultStatus,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            phase: UpdatePhase::Starting,
            last_attempt: None,
            last_successful_check: None,
            next_check: None,
            result: UpdateResultStatus::NeverChecked,
        }
    }
}

#[derive(Debug, Clone)]
pub enum UpdateEvent {
    CheckStarted {
        trigger: UpdateTrigger,
        at: SystemTime,
    },
    Current {
        installed_sequence: u64,
        offered_sequence: u64,
        at: SystemTime,
    },
    Installed {
        sequence: u64,
        version: String,
        at: SystemTime,
    },
    Failed {
        message: String,
        at: SystemTime,
    },
    Scheduled {
        at: SystemTime,
    },
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualTriggerResult {
    Queued,
    AlreadyQueued,
    AlreadyRunning,
    Stopped,
}

#[derive(Debug)]
pub enum UpdateClientError {
    Configuration(&'static str),
    InvalidUrl(&'static str),
    PayloadOriginNotAllowed,
    ResponseTooLarge {
        maximum: usize,
    },
    PayloadTooLarge {
        declared: u64,
        maximum: u64,
    },
    InvalidHttpStatus(u32),
    DeadlineExceeded,
    Cancelled,
    UnsupportedPlatform,
    Worker(io::Error),
    Http {
        operation: &'static str,
        source: io::Error,
    },
    Authentication(String),
    Definitions(String),
    Update(UpdateError),
}

impl fmt::Display for UpdateClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(reason) => {
                write!(formatter, "invalid update configuration: {reason}")
            }
            Self::InvalidUrl(reason) => write!(formatter, "invalid update URL: {reason}"),
            Self::PayloadOriginNotAllowed => {
                write!(formatter, "signed payload URL origin is not allowed")
            }
            Self::ResponseTooLarge { maximum } => write!(
                formatter,
                "update response exceeds the {maximum}-byte limit"
            ),
            Self::PayloadTooLarge { declared, maximum } => write!(
                formatter,
                "update payload declares {declared} bytes, exceeding the {maximum}-byte limit"
            ),
            Self::InvalidHttpStatus(status) => {
                write!(formatter, "update server returned HTTP status {status}")
            }
            Self::DeadlineExceeded => write!(formatter, "update request exceeded its deadline"),
            Self::Cancelled => write!(formatter, "update request was cancelled"),
            Self::UnsupportedPlatform => {
                write!(formatter, "native definition updates require Windows")
            }
            Self::Worker(source) => write!(formatter, "update worker could not start: {source}"),
            Self::Http { operation, source } => {
                write!(formatter, "WinHTTP {operation} failed: {source}")
            }
            Self::Authentication(reason) => {
                write!(formatter, "update manifest authentication failed: {reason}")
            }
            Self::Definitions(reason) => {
                write!(formatter, "definition validation failed: {reason}")
            }
            Self::Update(error) => write!(formatter, "update activation failed: {error}"),
        }
    }
}

impl std::error::Error for UpdateClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Worker(source) => Some(source),
            Self::Http { source, .. } => Some(source),
            Self::Update(error) => Some(error),
            _ => None,
        }
    }
}

impl From<UpdateError> for UpdateClientError {
    fn from(error: UpdateError) -> Self {
        Self::Update(error)
    }
}

enum ControlMessage {
    Trigger,
    Stop,
}

pub struct UpdateClientHandle {
    control: SyncSender<ControlMessage>,
    status: Arc<Mutex<UpdateStatus>>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl UpdateClientHandle {
    pub fn trigger(&self) -> ManualTriggerResult {
        if self.stopping.load(Ordering::Acquire) {
            return ManualTriggerResult::Stopped;
        }
        let running = with_status(&self.status, |status| {
            matches!(
                status.phase,
                UpdatePhase::DownloadingManifest
                    | UpdatePhase::AuthenticatingManifest
                    | UpdatePhase::DownloadingPayload
                    | UpdatePhase::ValidatingPayload
                    | UpdatePhase::Activating
            )
        });
        if running {
            return ManualTriggerResult::AlreadyRunning;
        }
        match self.control.try_send(ControlMessage::Trigger) {
            Ok(()) => ManualTriggerResult::Queued,
            Err(TrySendError::Full(_)) => ManualTriggerResult::AlreadyQueued,
            Err(TrySendError::Disconnected(_)) => ManualTriggerResult::Stopped,
        }
    }

    pub fn status(&self) -> UpdateStatus {
        with_status(&self.status, Clone::clone)
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.control.try_send(ControlMessage::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for UpdateClientHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn start_update_client(
    config: UpdateClientConfig,
    definitions: DefinitionStore,
    trusted_public_key: [u8; 32],
) -> Result<(UpdateClientHandle, Receiver<UpdateEvent>), UpdateClientError> {
    let config = ValidatedConfig::try_from(&config)?;
    VerifyingKey::from_bytes(&trusted_public_key)
        .map_err(|_| UpdateClientError::Configuration("trusted Ed25519 public key is invalid"))?;

    let (control_tx, control_rx) = mpsc::sync_channel(CONTROL_CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::sync_channel(EVENT_CHANNEL_CAPACITY);
    let status = Arc::new(Mutex::new(UpdateStatus::default()));
    let stopping = Arc::new(AtomicBool::new(false));
    let worker_status = Arc::clone(&status);
    let worker_stopping = Arc::clone(&stopping);

    let worker = thread::Builder::new()
        .name("blackshard-definition-updater".to_owned())
        .spawn(move || {
            update_worker(
                config,
                definitions,
                trusted_public_key,
                control_rx,
                event_tx,
                worker_status,
                worker_stopping,
            )
        })
        .map_err(UpdateClientError::Worker)?;

    Ok((
        UpdateClientHandle {
            control: control_tx,
            status,
            stopping,
            worker: Some(worker),
        },
        event_rx,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HttpsOrigin {
    host: String,
    port: u16,
}

impl HttpsOrigin {
    fn from_url(url: &Url) -> Result<Self, UpdateClientError> {
        validate_https_url(url)?;
        Ok(Self {
            host: url
                .host_str()
                .expect("validated URL has a host")
                .to_ascii_lowercase(),
            port: url.port_or_known_default().unwrap_or(443),
        })
    }

    fn parse_allowlisted(value: &str) -> Result<Self, UpdateClientError> {
        let url = parse_https_url(value)?;
        if (url.path() != "/" && !url.path().is_empty()) || url.query().is_some() {
            return Err(UpdateClientError::Configuration(
                "allowed payload entries must be bare HTTPS origins",
            ));
        }
        Self::from_url(&url)
    }
}

#[derive(Clone)]
struct ValidatedConfig {
    manifest_url: Url,
    manifest_origin: HttpsOrigin,
    allowed_payload_origins: HashSet<HttpsOrigin>,
    maximum_envelope_bytes: usize,
    maximum_payload_bytes: u64,
    timeouts: HttpTimeouts,
    scheduler: UpdateScheduler,
    check_on_start: bool,
    user_agent: String,
}

impl TryFrom<&UpdateClientConfig> for ValidatedConfig {
    type Error = UpdateClientError;

    fn try_from(config: &UpdateClientConfig) -> Result<Self, Self::Error> {
        let manifest_url = parse_https_url(&config.manifest_url)?;
        let manifest_origin = HttpsOrigin::from_url(&manifest_url)?;
        if config.maximum_envelope_bytes == 0 || config.maximum_envelope_bytes > MAX_ENVELOPE_BYTES
        {
            return Err(UpdateClientError::Configuration(
                "manifest limit must be between 1 byte and MAX_ENVELOPE_BYTES",
            ));
        }
        if config.maximum_payload_bytes == 0
            || config.maximum_payload_bytes > MAX_DEFINITION_PAYLOAD_BYTES as u64
        {
            return Err(UpdateClientError::Configuration(
                "payload limit must fit the definition payload limit",
            ));
        }
        validate_timeouts(config.timeouts)?;
        if config.scheduler.interval <= config.scheduler.maximum_jitter
            || config.scheduler.interval < Duration::from_secs(60)
        {
            return Err(UpdateClientError::Configuration(
                "update interval must exceed jitter and be at least one minute",
            ));
        }
        if config.user_agent.is_empty()
            || config.user_agent.len() > 128
            || config
                .user_agent
                .chars()
                .any(|character| character.is_control())
        {
            return Err(UpdateClientError::Configuration(
                "user agent must contain 1 through 128 non-control characters",
            ));
        }

        let mut allowed_payload_origins = HashSet::new();
        for value in &config.allowed_payload_origins {
            allowed_payload_origins.insert(HttpsOrigin::parse_allowlisted(value)?);
        }

        Ok(Self {
            manifest_url,
            manifest_origin,
            allowed_payload_origins,
            maximum_envelope_bytes: config.maximum_envelope_bytes,
            maximum_payload_bytes: config.maximum_payload_bytes,
            timeouts: config.timeouts,
            scheduler: config.scheduler,
            check_on_start: config.check_on_start,
            user_agent: config.user_agent.clone(),
        })
    }
}

fn validate_timeouts(timeouts: HttpTimeouts) -> Result<(), UpdateClientError> {
    for timeout in [
        timeouts.resolve,
        timeouts.connect,
        timeouts.send,
        timeouts.receive,
    ] {
        if !(MIN_OPERATION_TIMEOUT..=MAX_OPERATION_TIMEOUT).contains(&timeout) {
            return Err(UpdateClientError::Configuration(
                "each WinHTTP timeout must be between 100 ms and 60 seconds",
            ));
        }
    }
    if !(MIN_OVERALL_TIMEOUT..=MAX_OVERALL_TIMEOUT).contains(&timeouts.overall)
        || timeouts.overall
            < timeouts
                .resolve
                .max(timeouts.connect)
                .max(timeouts.send)
                .max(timeouts.receive)
    {
        return Err(UpdateClientError::Configuration(
            "overall timeout must be 1-300 seconds and no shorter than any operation timeout",
        ));
    }
    Ok(())
}

fn parse_https_url(value: &str) -> Result<Url, UpdateClientError> {
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        return Err(UpdateClientError::InvalidUrl(
            "URL length must be between 1 and 2048 bytes",
        ));
    }
    let (raw_scheme, raw_authority) =
        value
            .split_once("://")
            .ok_or(UpdateClientError::InvalidUrl(
                "an explicit HTTPS authority is required",
            ))?;
    if !raw_scheme.eq_ignore_ascii_case("https")
        || raw_authority.is_empty()
        || raw_authority.starts_with('/')
        || raw_authority.starts_with('?')
        || raw_authority.starts_with('#')
    {
        return Err(UpdateClientError::InvalidUrl(
            "an explicit HTTPS authority is required",
        ));
    }
    let url =
        Url::parse(value).map_err(|_| UpdateClientError::InvalidUrl("URL could not be parsed"))?;
    validate_https_url(&url)?;
    Ok(url)
}

fn validate_https_url(url: &Url) -> Result<(), UpdateClientError> {
    if url.scheme() != "https" {
        return Err(UpdateClientError::InvalidUrl("HTTPS is required"));
    }
    if url.host_str().is_none() {
        return Err(UpdateClientError::InvalidUrl("host is required"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UpdateClientError::InvalidUrl(
            "credentials in URLs are forbidden",
        ));
    }
    if url.fragment().is_some() {
        return Err(UpdateClientError::InvalidUrl("fragments are forbidden"));
    }
    Ok(())
}

fn payload_url(config: &ValidatedConfig, value: &str) -> Result<Url, UpdateClientError> {
    let url = parse_https_url(value)?;
    let origin = HttpsOrigin::from_url(&url)?;
    if origin != config.manifest_origin && !config.allowed_payload_origins.contains(&origin) {
        return Err(UpdateClientError::PayloadOriginNotAllowed);
    }
    Ok(url)
}

fn update_worker(
    config: ValidatedConfig,
    definitions: DefinitionStore,
    trusted_public_key: [u8; 32],
    control: Receiver<ControlMessage>,
    events: SyncSender<UpdateEvent>,
    status: Arc<Mutex<UpdateStatus>>,
    stopping: Arc<AtomicBool>,
) {
    if config.check_on_start
        && !run_one_check(
            UpdateTrigger::Startup,
            &config,
            &definitions,
            &trusted_public_key,
            &events,
            &status,
            &stopping,
        )
    {
        finish_worker(&events, &status);
        return;
    }

    loop {
        if stopping.load(Ordering::Acquire) {
            break;
        }
        let delay = config.scheduler.delay_for_sample(rand::rng().next_u64());
        let next_check = SystemTime::now()
            .checked_add(delay)
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(u64::MAX));
        mutate_status(&status, |value| {
            value.phase = UpdatePhase::Sleeping;
            value.next_check = Some(next_check);
        });
        emit(&events, UpdateEvent::Scheduled { at: next_check });

        let trigger = match control.recv_timeout(delay) {
            Ok(ControlMessage::Trigger) => UpdateTrigger::Manual,
            Ok(ControlMessage::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => UpdateTrigger::Scheduled,
        };
        if stopping.load(Ordering::Acquire) {
            break;
        }
        if !run_one_check(
            trigger,
            &config,
            &definitions,
            &trusted_public_key,
            &events,
            &status,
            &stopping,
        ) {
            break;
        }
    }

    finish_worker(&events, &status);
}

fn finish_worker(events: &SyncSender<UpdateEvent>, status: &Arc<Mutex<UpdateStatus>>) {
    mutate_status(status, |value| {
        value.phase = UpdatePhase::Stopped;
        value.next_check = None;
    });
    emit(events, UpdateEvent::Stopped);
}

fn run_one_check(
    trigger: UpdateTrigger,
    config: &ValidatedConfig,
    definitions: &DefinitionStore,
    trusted_public_key: &[u8; 32],
    events: &SyncSender<UpdateEvent>,
    status: &Arc<Mutex<UpdateStatus>>,
    stopping: &AtomicBool,
) -> bool {
    if stopping.load(Ordering::Acquire) {
        return false;
    }
    let attempt = SystemTime::now();
    mutate_status(status, |value| {
        value.phase = UpdatePhase::DownloadingManifest;
        value.last_attempt = Some(attempt);
        value.next_check = None;
    });
    emit(
        events,
        UpdateEvent::CheckStarted {
            trigger,
            at: attempt,
        },
    );

    let outcome = perform_update(config, definitions, trusted_public_key, stopping, |phase| {
        mutate_status(status, |value| value.phase = phase);
    });
    let completed = SystemTime::now();
    match outcome {
        Ok(CheckOutcome::Current {
            installed_sequence,
            offered_sequence,
        }) => {
            mutate_status(status, |value| {
                value.last_successful_check = Some(completed);
                value.result = UpdateResultStatus::Current {
                    sequence: installed_sequence,
                };
            });
            emit(
                events,
                UpdateEvent::Current {
                    installed_sequence,
                    offered_sequence,
                    at: completed,
                },
            );
            true
        }
        Ok(CheckOutcome::Installed(active)) => {
            mutate_status(status, |value| {
                value.last_successful_check = Some(completed);
                value.result = UpdateResultStatus::Installed {
                    sequence: active.sequence,
                    version: active.version.clone(),
                };
            });
            emit(
                events,
                UpdateEvent::Installed {
                    sequence: active.sequence,
                    version: active.version,
                    at: completed,
                },
            );
            true
        }
        Err(UpdateClientError::Cancelled) if stopping.load(Ordering::Acquire) => false,
        Err(error) => {
            let message = error.to_string();
            mutate_status(status, |value| {
                value.result = UpdateResultStatus::Failed {
                    message: message.clone(),
                };
            });
            emit(
                events,
                UpdateEvent::Failed {
                    message,
                    at: completed,
                },
            );
            true
        }
    }
}

enum CheckOutcome {
    Current {
        installed_sequence: u64,
        offered_sequence: u64,
    },
    Installed(ActiveUpdate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceDisposition {
    Current,
    Advance,
}

fn classify_offered_sequence(
    offered: u64,
    installed: u64,
) -> Result<SequenceDisposition, UpdateError> {
    match offered.cmp(&installed) {
        std::cmp::Ordering::Equal => Ok(SequenceDisposition::Current),
        std::cmp::Ordering::Greater => Ok(SequenceDisposition::Advance),
        std::cmp::Ordering::Less => Err(UpdateError::Rollback { offered, installed }),
    }
}

fn current_metadata_matches(active: &ActiveUpdate, offered: &UpdateManifest) -> bool {
    active.sequence == offered.sequence
        && active.version == offered.version
        && active.expires_at == offered.expires_at
        && active
            .payload_sha256
            .eq_ignore_ascii_case(&offered.payload_sha256)
}

fn perform_update(
    config: &ValidatedConfig,
    definitions: &DefinitionStore,
    trusted_public_key: &[u8; 32],
    stopping: &AtomicBool,
    mut set_phase: impl FnMut(UpdatePhase),
) -> Result<CheckOutcome, UpdateClientError> {
    ensure_running(stopping)?;
    let envelope_bytes = fetch_bounded(
        &config.manifest_url,
        config.maximum_envelope_bytes,
        config,
        stopping,
    )?;
    let envelope = SignedUpdateEnvelope::from_json(&envelope_bytes)?;

    set_phase(UpdatePhase::AuthenticatingManifest);
    let now = Utc::now();
    authenticate_manifest(
        &envelope,
        now,
        config.maximum_payload_bytes,
        trusted_public_key,
    )?;
    let payload_url = payload_url(config, &envelope.manifest.payload_url)?;

    let installed = definitions.update_store().current()?;
    let installed_sequence = installed.as_ref().map_or(0, |active| active.sequence);
    match classify_offered_sequence(envelope.manifest.sequence, installed_sequence)? {
        SequenceDisposition::Current => {
            if !installed
                .as_ref()
                .is_some_and(|active| current_metadata_matches(active, &envelope.manifest))
            {
                return Err(UpdateError::SequenceConflict {
                    sequence: envelope.manifest.sequence,
                }
                .into());
            }
            return Ok(CheckOutcome::Current {
                installed_sequence,
                offered_sequence: envelope.manifest.sequence,
            });
        }
        SequenceDisposition::Advance => {}
    }

    set_phase(UpdatePhase::DownloadingPayload);
    let declared_size = envelope.manifest.payload_size;
    let payload_limit =
        usize::try_from(declared_size).map_err(|_| UpdateClientError::PayloadTooLarge {
            declared: declared_size,
            maximum: config.maximum_payload_bytes,
        })?;
    let payload = fetch_bounded(&payload_url, payload_limit, config, stopping)?;

    set_phase(UpdatePhase::ValidatingPayload);
    verify_update(
        &envelope,
        &payload,
        installed_sequence,
        Utc::now(),
        config.maximum_payload_bytes,
        trusted_public_key,
    )?;
    DefinitionPayload::from_bytes(&payload)
        .map_err(|error| UpdateClientError::Definitions(error.to_string()))?;
    ensure_running(stopping)?;

    set_phase(UpdatePhase::Activating);
    let active = match definitions.update_store().stage_and_activate(
        &envelope,
        &payload,
        Utc::now(),
        trusted_public_key,
    ) {
        Ok(active) => active,
        Err(UpdateError::Rollback { offered, installed }) if offered == installed => {
            let current = definitions.update_store().current()?;
            if !current
                .as_ref()
                .is_some_and(|active| current_metadata_matches(active, &envelope.manifest))
            {
                return Err(UpdateError::SequenceConflict { sequence: offered }.into());
            }
            return Ok(CheckOutcome::Current {
                installed_sequence: installed,
                offered_sequence: offered,
            });
        }
        Err(error) => return Err(error.into()),
    };

    let loaded = definitions
        .load_with_defaults(Utc::now(), trusted_public_key)
        .map_err(|error| UpdateClientError::Definitions(error.to_string()))?;
    match loaded.source {
        DefinitionSource::Current { sequence, .. } if sequence == active.sequence => {
            Ok(CheckOutcome::Installed(active))
        }
        source => Err(UpdateClientError::Definitions(format!(
            "activated sequence {} was rejected; runtime selected {source:?}",
            active.sequence
        ))),
    }
}

fn authenticate_manifest(
    envelope: &SignedUpdateEnvelope,
    now: DateTime<Utc>,
    maximum_payload_bytes: u64,
    trusted_public_key: &[u8; 32],
) -> Result<(), UpdateClientError> {
    match verify_manifest(envelope, now, maximum_payload_bytes, trusted_public_key) {
        Ok(()) => Ok(()),
        Err(UpdateError::Oversized { declared, maximum }) => {
            Err(UpdateClientError::PayloadTooLarge { declared, maximum })
        }
        Err(error) => Err(UpdateClientError::Authentication(error.to_string())),
    }
}

fn ensure_running(stopping: &AtomicBool) -> Result<(), UpdateClientError> {
    if stopping.load(Ordering::Acquire) {
        Err(UpdateClientError::Cancelled)
    } else {
        Ok(())
    }
}

fn mutate_status(status: &Arc<Mutex<UpdateStatus>>, update: impl FnOnce(&mut UpdateStatus)) {
    let mut guard = status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    update(&mut guard);
}

fn with_status<T>(status: &Arc<Mutex<UpdateStatus>>, read: impl FnOnce(&UpdateStatus) -> T) -> T {
    let guard = status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    read(&guard)
}

fn emit(events: &SyncSender<UpdateEvent>, event: UpdateEvent) {
    let _ = events.try_send(event);
}

#[cfg(windows)]
fn fetch_bounded(
    url: &Url,
    maximum_bytes: usize,
    config: &ValidatedConfig,
    stopping: &AtomicBool,
) -> Result<Vec<u8>, UpdateClientError> {
    windows_http::fetch_bounded(url, maximum_bytes, config, stopping)
}

#[cfg(not(windows))]
fn fetch_bounded(
    _url: &Url,
    _maximum_bytes: usize,
    _config: &ValidatedConfig,
    _stopping: &AtomicBool,
) -> Result<Vec<u8>, UpdateClientError> {
    Err(UpdateClientError::UnsupportedPlatform)
}

#[cfg(windows)]
mod windows_http {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    type HInternet = *mut c_void;

    const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_OPTION_ENABLE_FEATURE: u32 = 79;
    const WINHTTP_OPTION_SECURE_PROTOCOLS: u32 = 84;
    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    const WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE: u32 = 91;
    const WINHTTP_ENABLE_SSL_REVOCATION: u32 = 1;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2: u32 = 0x0000_0800;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3: u32 = 0x0000_2000;
    const WINHTTP_OPTION_REDIRECT_POLICY_NEVER: u32 = 0;
    const MAX_RESPONSE_HEADER_BYTES: u32 = 64 * 1024;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(
            agent: *const u16,
            access_type: u32,
            proxy_name: *const u16,
            proxy_bypass: *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpCloseHandle(internet: HInternet) -> i32;
        fn WinHttpConnect(
            session: HInternet,
            server_name: *const u16,
            server_port: u16,
            reserved: u32,
        ) -> HInternet;
        fn WinHttpOpenRequest(
            connect: HInternet,
            verb: *const u16,
            object_name: *const u16,
            version: *const u16,
            referrer: *const u16,
            accept_types: *const *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpSetTimeouts(
            internet: HInternet,
            resolve_timeout: i32,
            connect_timeout: i32,
            send_timeout: i32,
            receive_timeout: i32,
        ) -> i32;
        fn WinHttpSetOption(
            internet: HInternet,
            option: u32,
            buffer: *mut c_void,
            buffer_length: u32,
        ) -> i32;
        fn WinHttpSendRequest(
            request: HInternet,
            headers: *const u16,
            headers_length: u32,
            optional: *mut c_void,
            optional_length: u32,
            total_length: u32,
            context: usize,
        ) -> i32;
        fn WinHttpReceiveResponse(request: HInternet, reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(
            request: HInternet,
            info_level: u32,
            name: *const u16,
            buffer: *mut c_void,
            buffer_length: *mut u32,
            index: *mut u32,
        ) -> i32;
        fn WinHttpReadData(
            request: HInternet,
            buffer: *mut c_void,
            bytes_to_read: u32,
            bytes_read: *mut u32,
        ) -> i32;
    }

    struct InternetHandle(HInternet);

    impl InternetHandle {
        fn new(handle: HInternet, operation: &'static str) -> Result<Self, UpdateClientError> {
            if handle.is_null() {
                Err(last_http_error(operation))
            } else {
                Ok(Self(handle))
            }
        }
    }

    impl Drop for InternetHandle {
        fn drop(&mut self) {
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }

    pub(super) fn fetch_bounded(
        url: &Url,
        maximum_bytes: usize,
        config: &ValidatedConfig,
        stopping: &AtomicBool,
    ) -> Result<Vec<u8>, UpdateClientError> {
        ensure_running(stopping)?;
        let started = Instant::now();
        let agent = wide(&config.user_agent);
        let session = InternetHandle::new(
            unsafe {
                WinHttpOpen(
                    agent.as_ptr(),
                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                    ptr::null(),
                    ptr::null(),
                    0,
                )
            },
            "session creation",
        )?;
        check_deadline(started, config.timeouts.overall, stopping)?;
        let timeouts = config.timeouts;
        if unsafe {
            WinHttpSetTimeouts(
                session.0,
                timeout_millis(timeouts.resolve),
                timeout_millis(timeouts.connect),
                timeout_millis(timeouts.send),
                timeout_millis(timeouts.receive),
            )
        } == 0
        {
            return Err(last_http_error("timeout configuration"));
        }

        // TLS 1.2 or 1.3, never older. Windows 10 builds whose WinHTTP predates TLS 1.3 reject the
        // flag outright, so those fall back to 1.2 alone rather than failing every update.
        let set_protocols = |mut protocols: u32| unsafe {
            WinHttpSetOption(
                session.0,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                (&mut protocols as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
            ) != 0
        };
        if !set_protocols(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            && !set_protocols(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2)
        {
            return Err(last_http_error("TLS policy configuration"));
        }

        let host = wide(url.host_str().expect("validated URL has a host"));
        let connection = InternetHandle::new(
            unsafe {
                WinHttpConnect(
                    session.0,
                    host.as_ptr(),
                    url.port_or_known_default().unwrap_or(443),
                    0,
                )
            },
            "connection creation",
        )?;
        check_deadline(started, config.timeouts.overall, stopping)?;

        let verb = wide("GET");
        let object_name = wide(&request_target(url));
        let request = InternetHandle::new(
            unsafe {
                WinHttpOpenRequest(
                    connection.0,
                    verb.as_ptr(),
                    object_name.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    WINHTTP_FLAG_SECURE,
                )
            },
            "request creation",
        )?;
        let mut redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_REDIRECT_POLICY,
                (&mut redirect_policy as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        } == 0
        {
            return Err(last_http_error("redirect policy configuration"));
        }
        let mut revocation = WINHTTP_ENABLE_SSL_REVOCATION;
        if unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_ENABLE_FEATURE,
                (&mut revocation as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        } == 0
        {
            return Err(last_http_error("certificate revocation configuration"));
        }
        let mut maximum_header_bytes = MAX_RESPONSE_HEADER_BYTES;
        if unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
                (&mut maximum_header_bytes as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        } == 0
        {
            return Err(last_http_error("response header limit configuration"));
        }

        let headers = wide("Accept: application/json\r\nCache-Control: no-cache\r\n");
        if unsafe {
            WinHttpSendRequest(
                request.0,
                headers.as_ptr(),
                u32::MAX,
                ptr::null_mut(),
                0,
                0,
                0,
            )
        } == 0
        {
            return Err(last_http_error("request send"));
        }
        check_deadline(started, config.timeouts.overall, stopping)?;
        if unsafe { WinHttpReceiveResponse(request.0, ptr::null_mut()) } == 0 {
            return Err(last_http_error("response receive"));
        }
        check_deadline(started, config.timeouts.overall, stopping)?;

        let mut status_code = 0_u32;
        let mut status_size = std::mem::size_of::<u32>() as u32;
        if unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                ptr::null(),
                (&mut status_code as *mut u32).cast(),
                &mut status_size,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_http_error("status query"));
        }
        if status_code != 200 {
            return Err(UpdateClientError::InvalidHttpStatus(status_code));
        }

        let mut output = Vec::with_capacity(maximum_bytes.min(HTTP_READ_CHUNK_BYTES));
        let mut buffer = [0_u8; HTTP_READ_CHUNK_BYTES];
        loop {
            check_deadline(started, config.timeouts.overall, stopping)?;

            let remaining_plus_one = maximum_bytes.saturating_sub(output.len()).saturating_add(1);
            let requested = buffer.len().min(remaining_plus_one).max(1);
            let mut received = 0_u32;
            if unsafe {
                WinHttpReadData(
                    request.0,
                    buffer.as_mut_ptr().cast(),
                    requested as u32,
                    &mut received,
                )
            } == 0
            {
                return Err(last_http_error("response body read"));
            }
            check_deadline(started, config.timeouts.overall, stopping)?;
            if received == 0 {
                break;
            }
            let received = received as usize;
            if output.len().saturating_add(received) > maximum_bytes {
                return Err(UpdateClientError::ResponseTooLarge {
                    maximum: maximum_bytes,
                });
            }
            output.extend_from_slice(&buffer[..received]);
        }
        Ok(output)
    }

    fn request_target(url: &Url) -> String {
        let mut target = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        target
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn timeout_millis(duration: Duration) -> i32 {
        duration.as_millis().min(i32::MAX as u128) as i32
    }

    fn check_deadline(
        started: Instant,
        overall: Duration,
        stopping: &AtomicBool,
    ) -> Result<(), UpdateClientError> {
        ensure_running(stopping)?;
        if started.elapsed() > overall {
            Err(UpdateClientError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    fn last_http_error(operation: &'static str) -> UpdateClientError {
        UpdateClientError::Http {
            operation,
            source: io::Error::last_os_error(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::UPDATE_SCHEMA_VERSION;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn requires_clean_https_urls() {
        assert!(parse_https_url("https://updates.blackshard.dev/manifest.json").is_ok());
        assert!(parse_https_url("http://updates.blackshard.dev/manifest.json").is_err());
        assert!(parse_https_url("https://user:secret@updates.blackshard.dev/x").is_err());
        assert!(parse_https_url("https://updates.blackshard.dev/x#fragment").is_err());
        assert!(parse_https_url("https:///missing-host").is_err());
    }

    #[test]
    fn payload_must_share_origin_or_match_exact_allowlist() {
        let mut public =
            UpdateClientConfig::new("https://updates.blackshard.dev/releases/manifest.json");
        public.allowed_payload_origins = vec!["https://cdn.blackshard.dev".to_owned()];
        let config = ValidatedConfig::try_from(&public).unwrap();

        assert!(payload_url(
            &config,
            "https://updates.blackshard.dev/releases/definitions.json"
        )
        .is_ok());
        assert!(payload_url(&config, "https://cdn.blackshard.dev/definitions.json").is_ok());
        assert!(payload_url(&config, "https://cdn.blackshard.dev:444/definitions.json").is_err());
        assert!(payload_url(&config, "https://evil.example/definitions.json").is_err());
        assert!(payload_url(&config, "http://updates.blackshard.dev/definitions.json").is_err());
    }

    #[test]
    fn allowlist_entries_are_origins_not_url_prefixes() {
        let mut config = UpdateClientConfig::new("https://updates.blackshard.dev/manifest.json");
        config.allowed_payload_origins = vec!["https://cdn.blackshard.dev/path".to_owned()];
        assert!(config.validate().is_err());
        config.allowed_payload_origins = vec!["https://cdn.blackshard.dev?token=secret".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn response_and_timeout_limits_are_bounded() {
        let mut config = UpdateClientConfig::new("https://updates.blackshard.dev/manifest.json");
        config.maximum_envelope_bytes = MAX_ENVELOPE_BYTES + 1;
        assert!(config.validate().is_err());

        config.maximum_envelope_bytes = MAX_ENVELOPE_BYTES;
        config.maximum_payload_bytes = MAX_DEFINITION_PAYLOAD_BYTES as u64 + 1;
        assert!(config.validate().is_err());

        config.maximum_payload_bytes = MAX_DEFINITION_PAYLOAD_BYTES as u64;
        config.timeouts.receive = Duration::from_secs(61);
        assert!(config.validate().is_err());
    }

    #[test]
    fn embedded_endpoint_constructor_has_no_fallback() {
        assert!(UpdateClientConfig::from_embedded_endpoint(
            "https://updates.blackshard.dev/manifest.json"
        )
        .is_ok());
        assert!(UpdateClientConfig::from_embedded_endpoint("").is_err());
    }

    #[test]
    fn sleeping_worker_stops_without_waiting_for_the_schedule() {
        let directory = tempfile::tempdir().unwrap();
        let definitions = DefinitionStore::new(directory.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let mut config = UpdateClientConfig::new("https://updates.blackshard.dev/manifest.json");
        config.check_on_start = false;
        let (handle, events) =
            start_update_client(config, definitions, key.verifying_key().to_bytes()).unwrap();
        let started = Instant::now();
        handle.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(events
            .try_iter()
            .any(|event| matches!(event, UpdateEvent::Stopped)));
    }

    #[test]
    fn four_hour_schedule_has_symmetric_bounded_jitter() {
        let scheduler = UpdateScheduler::default();
        let minimum = scheduler.interval - scheduler.maximum_jitter;
        let maximum = scheduler.interval + scheduler.maximum_jitter;
        for sample in [0, 1, u64::MAX / 2, u64::MAX] {
            let delay = scheduler.delay_for_sample(sample);
            assert!(delay >= minimum);
            assert!(delay <= maximum);
        }
        assert_eq!(scheduler.delay_for_sample(0), minimum);
    }

    #[test]
    fn preflight_authenticates_before_current_shortcut() {
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let payload = b"{}";
        let now = Utc.timestamp_opt(1_900_000_000, 0).single().unwrap();
        let manifest = crate::updater::UpdateManifest {
            schema_version: UPDATE_SCHEMA_VERSION,
            product: crate::updater::UPDATE_PRODUCT_ID.to_owned(),
            channel: crate::updater::UPDATE_CHANNEL.to_owned(),
            sequence: 42,
            version: "2030.01.01".to_owned(),
            issued_at: now,
            expires_at: now + chrono::Duration::hours(8),
            payload_url: "https://updates.blackshard.dev/definitions.json".to_owned(),
            payload_size: payload.len() as u64,
            payload_sha256: hex::encode(Sha256::digest(payload)),
        };
        let signature = key.sign(&manifest.signing_bytes().unwrap());
        let mut envelope = SignedUpdateEnvelope {
            manifest,
            signature_ed25519: hex::encode(signature.to_bytes()),
        };
        assert!(authenticate_manifest(
            &envelope,
            now,
            MAX_DEFINITION_PAYLOAD_BYTES as u64,
            &key.verifying_key().to_bytes(),
        )
        .is_ok());

        envelope.manifest.version.push_str("-tampered");
        assert!(authenticate_manifest(
            &envelope,
            now,
            MAX_DEFINITION_PAYLOAD_BYTES as u64,
            &key.verifying_key().to_bytes(),
        )
        .is_err());
    }

    #[test]
    fn only_equal_sequence_is_current_and_lower_is_rollback() {
        assert_eq!(
            classify_offered_sequence(42, 42).unwrap(),
            SequenceDisposition::Current
        );
        assert_eq!(
            classify_offered_sequence(43, 42).unwrap(),
            SequenceDisposition::Advance
        );
        assert!(matches!(
            classify_offered_sequence(41, 42),
            Err(UpdateError::Rollback {
                offered: 41,
                installed: 42
            })
        ));
    }

    #[test]
    fn current_sequence_requires_identical_content_metadata() {
        let now = Utc.timestamp_opt(1_900_000_000, 0).single().unwrap();
        let active = ActiveUpdate {
            sequence: 42,
            version: "2030.01.01".to_owned(),
            expires_at: now + chrono::Duration::hours(8),
            payload_sha256: "ab".repeat(32),
            payload_path: std::path::PathBuf::from("payload"),
            envelope_path: std::path::PathBuf::from("envelope"),
        };
        let mut offered = crate::updater::UpdateManifest {
            schema_version: UPDATE_SCHEMA_VERSION,
            product: crate::updater::UPDATE_PRODUCT_ID.to_owned(),
            channel: crate::updater::UPDATE_CHANNEL.to_owned(),
            sequence: 42,
            version: active.version.clone(),
            issued_at: now,
            expires_at: active.expires_at,
            payload_url: "https://updates.blackshard.dev/definitions.json".to_owned(),
            payload_size: 1,
            payload_sha256: active.payload_sha256.to_ascii_uppercase(),
        };
        assert!(current_metadata_matches(&active, &offered));
        offered.payload_sha256 = "cd".repeat(32);
        assert!(!current_metadata_matches(&active, &offered));
    }
}
