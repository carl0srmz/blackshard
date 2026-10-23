use crate::atomic_file;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

pub const SERVICE_NAME: &str = "blackshard-protection-service";
pub const SERVICE_HEALTH_SCHEMA_VERSION: u32 = 4;
pub const SERVICE_HEALTH_FILE_NAME: &str = "service-health.json";

static HEALTH_WRITE_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);
const MAX_SERVICE_HEALTH_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceLifecycle {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceConnection {
    Connecting,
    Connected,
    Disconnected,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServiceDefinitionHealth {
    BuiltIn {
        version: String,
    },
    Updating {
        current_version: Option<String>,
    },
    Current {
        version: String,
        bundle_id: String,
        expires_at: DateTime<Utc>,
    },
    LastKnownGood {
        version: String,
        bundle_id: String,
        expires_at: DateTime<Utc>,
    },
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceCounters {
    pub scanned: u64,
    pub suspicious: u64,
    pub detected: u64,
    pub blocked_replies: u64,
    pub quarantined: u64,
    pub scan_errors: u64,
    pub bypassed_due_to_load: u64,
    pub driver_scan_requests: u64,
    pub driver_blocks: u64,
    pub driver_timeouts: u64,
    pub service_unavailable_bypasses: u64,
    pub object_resolution_bypasses: u64,
    pub oversize_path_bypasses: u64,
    pub irql_bypasses: u64,
    pub invalid_driver_replies: u64,
    pub dirty_writes: u64,
    pub enforcement_bypasses: u64,
    pub content_race_blocks: u64,
    pub path_resolution_failures: u64,
    pub driver_protocol_mismatches: u64,
    pub driver_cache_allows: u64,
    pub driver_boot_policy_allows: u64,
    pub required_enforcement_blocks: u64,
    pub driver_queue_overloads: u64,
    pub driver_ready_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceHealthSnapshot {
    pub schema_version: u32,
    pub product_version: String,
    pub process_id: u32,
    pub lifecycle: ServiceLifecycle,
    pub connection: ServiceConnection,
    pub connection_detail: Option<String>,
    pub real_time_enabled: bool,
    pub external_rules_suppressed: bool,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_detection_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub definitions: ServiceDefinitionHealth,
    pub counters: ServiceCounters,
    #[serde(default)]
    pub readiness: Option<crate::readiness::ReadinessState>,
    #[serde(default)]
    pub definition_database_version: Option<String>,
    /// How much of the machine this install can watch. Defaults to `Kernel` so a snapshot written
    /// by an older build is not mistaken for a driverless install.
    #[serde(default)]
    pub tier: crate::readiness::ProtectionTier,
}

impl ServiceHealthSnapshot {
    fn starting(started_at: DateTime<Utc>, real_time_enabled: bool) -> Self {
        Self {
            schema_version: SERVICE_HEALTH_SCHEMA_VERSION,
            product_version: crate::product_version(),
            process_id: std::process::id(),
            lifecycle: ServiceLifecycle::StartPending,
            connection: ServiceConnection::Connecting,
            connection_detail: None,
            real_time_enabled,
            external_rules_suppressed: false,
            started_at,
            updated_at: started_at,
            last_detection_at: None,
            last_error: None,
            definitions: ServiceDefinitionHealth::BuiltIn {
                version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
            },
            counters: ServiceCounters::default(),
            readiness: Some(crate::readiness::ReadinessState::Starting),
            definition_database_version: None,
            tier: crate::readiness::ProtectionTier::default(),
        }
    }
}

pub fn service_health_path_from_program_data(program_data: &Path) -> PathBuf {
    program_data
        .join("blackshard")
        .join(SERVICE_HEALTH_FILE_NAME)
}

pub fn default_service_health_path() -> PathBuf {
    let program_data = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    service_health_path_from_program_data(&program_data)
}

pub fn read_service_health(path: &Path) -> io::Result<ServiceHealthSnapshot> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service health is not a regular, non-symlink file",
        ));
    }
    if metadata.len() > MAX_SERVICE_HEALTH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service health exceeds its size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(MAX_SERVICE_HEALTH_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SERVICE_HEALTH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service health exceeds its size limit",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub fn write_service_health_atomic(
    path: &Path,
    snapshot: &ServiceHealthSnapshot,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(snapshot).map_err(io::Error::other)?;
    bytes.push(b'\n');
    atomic_file::write(path, &bytes)
}

#[cfg(windows)]
mod windows_service_host {
    use super::*;
    use crate::config::Settings;
    use crate::definitions::{configured_trusted_public_key, DefinitionSource, DefinitionStore};
    use crate::detection::{DetectionEngine, DetectionVerdict};
    use crate::history::{EventHistory, EventKind, SecurityEvent};
    use crate::ipc::{RpcServer, RpcServiceResources};
    use crate::quarantine::QuarantineStore;
    use crate::realtime::{
        new_shared_detection_engine, replace_detection_engine, ProtectionConnection,
        RealtimeCounters, RealtimeEvent, RealtimeProtection, SharedDetectionEngine,
    };
    use crate::update_client::{
        start_update_client, ManualTriggerResult, UpdateClientConfig, UpdateClientHandle,
        UpdateEvent,
    };
    use crate::updater::UpdateScheduler;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicBool, AtomicU8};
    use std::sync::{mpsc, Arc, Mutex, RwLock};
    use std::time::{Duration, Instant, SystemTime};
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const HEALTH_WRITE_INTERVAL: Duration = Duration::from_secs(2);
    const SETTINGS_CHECK_INTERVAL: Duration = Duration::from_secs(5);
    const STOP_WAIT_HINT: Duration = Duration::from_secs(30);
    const MANUAL_UPDATE_COOLDOWN: Duration = Duration::from_secs(5 * 60);
    /// How often an expired bundle is looked at again for a newer one that was installed meanwhile.
    const VAULT_PURGE_INTERVAL: Duration = Duration::from_secs(10 * 60);
    const EXPIRED_RELOAD_INTERVAL: Duration = Duration::from_secs(10 * 60);
    const REALTIME_EVENT_CHANNEL_CAPACITY: usize = 256;
    const UPDATE_MANIFEST_URL: Option<&str> = option_env!("BLACKSHARD_UPDATE_MANIFEST_URL");
    const UPDATE_ALLOWED_ORIGINS: Option<&str> = option_env!("BLACKSHARD_UPDATE_ALLOWED_ORIGINS");

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    enum BodyState {
        StartPending = 0,
        Running = 1,
        StopPending = 2,
        Stopped = 3,
    }

    impl BodyState {
        fn from_raw(value: u8) -> Self {
            match value {
                1 => Self::Running,
                2 => Self::StopPending,
                3 => Self::Stopped,
                _ => Self::StartPending,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SettingsStamp {
        length: u64,
        modified: Option<SystemTime>,
    }

    define_windows_service!(blackshard_service_main, service_main);

    pub fn run_service_dispatcher() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, blackshard_service_main)
    }

    pub fn run_service_console(stop_requested: Arc<AtomicBool>) -> Result<(), String> {
        run_service_body(stop_requested)
    }

    pub fn run_service_body(stop_requested: Arc<AtomicBool>) -> Result<(), String> {
        run_service_body_with_reporter(stop_requested, |_| Ok(()))
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_registered_service() {
            append_service_error(format!("blackshard service stopped with an error: {error}"));
        }
    }

    fn run_registered_service() -> Result<(), String> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let lifecycle = Arc::new(AtomicU8::new(BodyState::StartPending as u8));
        let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));

        let handler_stop = Arc::clone(&stop_requested);
        let handler_lifecycle = Arc::clone(&lifecycle);
        let handler_status = Arc::clone(&status_slot);
        let event_handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Interrogate => {
                    if let Ok(slot) = handler_status.lock() {
                        if let Some(handle) = *slot {
                            let state =
                                BodyState::from_raw(handler_lifecycle.load(Ordering::Acquire));
                            let _ = handle.set_service_status(service_status(state, false, None));
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    handler_stop.store(true, Ordering::Release);
                    handler_lifecycle.store(BodyState::StopPending as u8, Ordering::Release);
                    if let Ok(slot) = handler_status.lock() {
                        if let Some(handle) = *slot {
                            let _ = handle.set_service_status(service_status(
                                BodyState::StopPending,
                                false,
                                Some(1),
                            ));
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .map_err(|error| format!("could not register the SCM control handler: {error}"))?;
        if let Ok(mut slot) = status_slot.lock() {
            *slot = Some(status_handle);
        }

        let result = run_service_body_with_reporter(stop_requested, |state| {
            lifecycle.store(state as u8, Ordering::Release);
            status_handle
                .set_service_status(service_status(state, false, None))
                .map_err(|error| format!("could not report {state:?} to the SCM: {error}"))
        });

        if result.is_err() {
            lifecycle.store(BodyState::Stopped as u8, Ordering::Release);
            let _ =
                status_handle.set_service_status(service_status(BodyState::Stopped, true, None));
        }
        result
    }

    fn service_status(
        state: BodyState,
        failed: bool,
        checkpoint_override: Option<u32>,
    ) -> ServiceStatus {
        let (current_state, controls_accepted, checkpoint, wait_hint) = match state {
            BodyState::StartPending => (
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                1,
                Duration::from_secs(20),
            ),
            BodyState::Running => (
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                0,
                Duration::ZERO,
            ),
            BodyState::StopPending => (
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                2,
                STOP_WAIT_HINT,
            ),
            BodyState::Stopped => (
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::ZERO,
            ),
        };
        ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state,
            controls_accepted,
            exit_code: if failed {
                ServiceExitCode::ServiceSpecific(1)
            } else {
                ServiceExitCode::NO_ERROR
            },
            checkpoint: checkpoint_override.unwrap_or(checkpoint),
            wait_hint,
            process_id: None,
        }
    }

    fn run_service_body_with_reporter<F>(
        stop_requested: Arc<AtomicBool>,
        mut report_state: F,
    ) -> Result<(), String>
    where
        F: FnMut(BodyState) -> Result<(), String>,
    {
        apply_process_self_defense();
        let readiness = crate::readiness::ReadinessMonitor::new();
        readiness.update_state(crate::readiness::ReadinessState::Starting);
        report_state(BodyState::StartPending)?;
        log::info!("blackshard service is starting");

        // Earlier builds kept settings, history and shards where every user could read them.
        match crate::paths::migrate_into_state(
            &crate::paths::data_root(),
            &crate::paths::state_dir(),
            &crate::paths::FILES_MOVED_TO_STATE,
        ) {
            Ok(moved) if !moved.is_empty() => {
                log::info!("Moved {moved:?} into the private State folder")
            }
            Ok(_) => {}
            Err(error) => log::warn!("Could not move data into the private State folder: {error}"),
        }

        // The safety copies ransomware rollback depends on. Without them protection still works,
        // it just cannot undo damage.
        if let Err(error) = crate::rollback::init(crate::paths::state_dir().join("Rollback")) {
            log::warn!("Ransomware rollback is unavailable: {error}");
        }

        let health_path = default_service_health_path();
        let started_at = Utc::now();
        let history = Arc::new(EventHistory::default_for_machine());
        let settings_path = Settings::default_machine_path();
        readiness.update_state(crate::readiness::ReadinessState::LoadingSettings);
        let initial_settings = match Settings::load(&settings_path) {
            Ok(settings) => settings,
            Err(error) => {
                let message =
                    format!("Settings could not be loaded; secure defaults are active: {error}");
                append_error(&history, &message);
                Settings::default()
            }
        };
        let settings_stamp = settings_stamp(&settings_path);
        let settings = Arc::new(RwLock::new(initial_settings));
        let real_time_enabled = settings
            .read()
            .map(|value| value.real_time_protection)
            .unwrap_or(true);

        // The minifilter's presence decides how much of the machine can be watched. Detected once
        // here rather than re-derived, so every later decision agrees on the tier.
        let tier = crate::readiness::detect_protection_tier();
        log::info!(
            "Protection tier: {:?} (real-time coverage: {})",
            tier,
            tier.coverage_summary()
        );

        let mut snapshot = ServiceHealthSnapshot::starting(started_at, real_time_enabled);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        snapshot.tier = tier;
        write_health_best_effort(&health_path, &snapshot, &history);

        readiness.update_state(crate::readiness::ReadinessState::LoadingFreshClam);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        write_health_best_effort(&health_path, &snapshot, &history);

        let program_data = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let blackshard_data = program_data.join("blackshard");
        // Start on the definitions already on disk. Fetching first would hold the service in
        // START_PENDING for as long as a 300 MB download takes; the scheduler fetches in the
        // background instead and hands over the new generation when it lands.
        let mut active_freshclam =
            crate::clamdb::downloader::active_database(&blackshard_data).ok();
        let freshclam_receiver = crate::clamdb::scheduler::start_scheduler(blackshard_data.clone());

        match crate::shards::load(&crate::shards::default_machine_path()) {
            Ok(count) => log::info!("Loaded {count} locally learned shards"),
            Err(error) => append_error(
                &history,
                &format!("Learned shards could not be loaded; none are active: {error}"),
            ),
        }
        readiness.update_state(crate::readiness::ReadinessState::LoadingDefinitions);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        let engine = match load_detection_engine(&mut snapshot, &history) {
            Ok(engine) => {
                let engine = if let Some(active) = active_freshclam.as_ref() {
                    match load_native_index(active) {
                        Ok(index) => engine.with_native_index(index),
                        Err(error) => {
                            log::warn!("ClamAV native SHA-256 index was not loaded: {error}");
                            engine
                        }
                    }
                } else {
                    engine
                };
                new_shared_detection_engine(engine)
            }
            Err(error) => {
                let message = format!("Detection engine initialization failed: {error}");
                log::error!("{message}");
                readiness.update_state(crate::readiness::ReadinessState::Failed {
                    reason: message.clone(),
                });
                snapshot.lifecycle = ServiceLifecycle::Stopped;
                snapshot.connection = ServiceConnection::Stopped;
                snapshot.updated_at = Utc::now();
                snapshot.last_error = Some(message.clone());
                snapshot.readiness = Some(readiness.diagnostics().current_state);
                write_health_best_effort(&health_path, &snapshot, &history);
                return Err(message);
            }
        };
        readiness.update_state(crate::readiness::ReadinessState::StartingDetectionWorkers);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        let quarantine = Arc::new(QuarantineStore::default_for_machine());
        let (event_sender, event_receiver) = mpsc::sync_channel(REALTIME_EVENT_CHANNEL_CAPACITY);
        let definition_generation = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let verdict_cache = crate::verdict_cache::VerdictCache::new(100_000);
        let mut protection = if tier.requires_driver() {
            RealtimeProtection::start(
                Arc::clone(&engine),
                Arc::clone(&quarantine),
                Arc::clone(&history),
                Arc::clone(&settings),
                event_sender,
                Arc::clone(&verdict_cache),
                Arc::clone(&definition_generation),
            )
        } else {
            RealtimeProtection::without_driver()
        };
        let counters = Arc::clone(&protection.counters);
        let (mut update_client, update_receiver) =
            start_definition_updater(&settings, &mut snapshot, &history);
        let mut stable_definitions = snapshot.definitions.clone();
        let (rpc_update_sender, rpc_update_receiver) = mpsc::sync_channel(1);

        readiness.update_state(crate::readiness::ReadinessState::ValidatingProtocol);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        let rpc_server = match RpcServer::start(RpcServiceResources::new(
            Arc::clone(&engine),
            Arc::clone(&quarantine),
            Arc::clone(&history),
            Arc::clone(&settings),
            settings_path.clone(),
            rpc_update_sender,
            update_client.is_some(),
        )) {
            Ok(server) => server,
            Err(error) => {
                if let Some(client) = update_client.take() {
                    client.stop();
                }
                protection.stop();
                readiness.update_state(crate::readiness::ReadinessState::Failed {
                    reason: error.clone(),
                });
                snapshot.lifecycle = ServiceLifecycle::Stopped;
                snapshot.connection = ServiceConnection::Stopped;
                snapshot.updated_at = Utc::now();
                snapshot.last_error = Some(error.clone());
                snapshot.readiness = Some(readiness.diagnostics().current_state);
                write_health_best_effort(&health_path, &snapshot, &history);
                return Err(error);
            }
        };
        let mut last_manual_update = None::<Instant>;
        let mut last_expired_reload = None::<Instant>;
        let mut last_vault_purge = Instant::now();
        let mut expiry_reported = false;

        readiness.update_state(crate::readiness::ReadinessState::ConnectingDriver);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        snapshot.lifecycle = ServiceLifecycle::Running;
        snapshot.updated_at = Utc::now();
        snapshot.counters = counter_snapshot(&counters, &protection, &mut snapshot.last_error);
        write_health_best_effort(&health_path, &snapshot, &history);
        if let Err(error) = report_state(BodyState::Running) {
            rpc_server.stop();
            if let Some(client) = update_client.take() {
                client.stop();
            }
            protection.stop();
            readiness.update_state(crate::readiness::ReadinessState::Failed {
                reason: error.clone(),
            });
            snapshot.lifecycle = ServiceLifecycle::Stopped;
            snapshot.connection = ServiceConnection::Stopped;
            snapshot.updated_at = Utc::now();
            snapshot.last_error = Some(error.clone());
            snapshot.counters = counter_snapshot(&counters, &protection, &mut snapshot.last_error);
            snapshot.readiness = Some(readiness.diagnostics().current_state);
            write_health_best_effort(&health_path, &snapshot, &history);
            return Err(error);
        }

        let mut last_health_write = Instant::now();
        let mut last_settings_check = Instant::now();
        let mut observed_settings_stamp = settings_stamp;
        let mut runtime_error = None;
        let mut consecutive_health_successes = 0u32;
        let mut consecutive_health_failures = 0u32;
        let mut self_test_passed = false;
        let mut last_self_test_attempt = None::<Instant>;
        let mut last_version_refresh = None::<Instant>;
        while !stop_requested.load(Ordering::Acquire) {
            let mut changed = false;
            match event_receiver.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => changed |= apply_realtime_event(&mut snapshot, event),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let error = "real-time protection event channel disconnected".to_owned();
                    snapshot.connection = ServiceConnection::Disconnected;
                    snapshot.connection_detail = Some(error.clone());
                    snapshot.last_error = Some(error.clone());
                    runtime_error = Some(error);
                    changed = true;
                }
            }
            while let Ok(event) = event_receiver.try_recv() {
                changed |= apply_realtime_event(&mut snapshot, event);
            }

            while let Ok(update) = freshclam_receiver.try_recv() {
                let active = match update {
                    Ok(active) => active,
                    Err(error) => {
                        let message = format!("ClamAV definition download failed: {error}");
                        append_error(&history, &message);
                        snapshot.last_error = Some(message);
                        changed = true;
                        continue;
                    }
                };
                match load_native_index(&active) {
                    Ok(index) => {
                        if let Ok(current) = engine.read() {
                            current.replace_native_index(index);
                        }
                        active_freshclam = Some(active);
                        definition_generation.fetch_add(1, std::sync::atomic::Ordering::Release);
                        changed = true;
                    }
                    Err(error) => {
                        let message = format!("FreshClam index activation failed: {error}");
                        append_error(&history, &message);
                        snapshot.last_error = Some(message);
                        changed = true;
                    }
                }
            }

            if let Some(receiver) = &update_receiver {
                while let Ok(event) = receiver.try_recv() {
                    changed |= apply_update_event(
                        &mut snapshot,
                        &mut stable_definitions,
                        event,
                        &engine,
                        &history,
                        &definition_generation,
                    );
                }
            }

            if definitions_expired(&stable_definitions, Utc::now())
                && last_expired_reload.is_none_or(|at| at.elapsed() >= EXPIRED_RELOAD_INTERVAL)
            {
                last_expired_reload = Some(Instant::now());
                match load_detection_engine(&mut snapshot, &history) {
                    Ok(fresh) => {
                        // Still the same expired bundle: keep the engine already running rather
                        // than recompiling every rule to arrive at it again.
                        if snapshot.definitions != stable_definitions {
                            replace_detection_engine(&engine, fresh);
                            definition_generation
                                .fetch_add(1, std::sync::atomic::Ordering::Release);
                            stable_definitions = snapshot.definitions.clone();
                        }
                        if definitions_expired(&stable_definitions, Utc::now()) && !expiry_reported
                        {
                            expiry_reported = true;
                            let message = "Definitions have expired and could not be refreshed; \
                                 the last authenticated set is still in use. Connect to the \
                                 internet so blackshard can update."
                                .to_owned();
                            append_error(&history, &message);
                            snapshot.last_error = Some(message);
                        } else if !definitions_expired(&stable_definitions, Utc::now()) {
                            expiry_reported = false;
                        }
                    }
                    Err(error) => {
                        match DetectionEngine::builtin() {
                            Ok(built_in) => {
                                replace_detection_engine(&engine, built_in);
                                definition_generation
                                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                                stable_definitions = ServiceDefinitionHealth::BuiltIn {
                                    version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
                                };
                                snapshot.definitions = stable_definitions.clone();
                            }
                            Err(built_in_error) => {
                                snapshot.definitions = ServiceDefinitionHealth::Failed {
                                    detail: built_in_error.clone(),
                                };
                                runtime_error = Some(built_in_error);
                            }
                        }
                        snapshot.last_error = Some(format!(
                            "expired definitions were retired; authenticated reload failed: {error}"
                        ));
                        append_error(&history, snapshot.last_error.as_deref().unwrap_or(&error));
                    }
                }
                changed = true;
            }

            while rpc_update_receiver.try_recv().is_ok() {
                let allowed = last_manual_update
                    .is_none_or(|attempt| attempt.elapsed() >= MANUAL_UPDATE_COOLDOWN);
                if allowed {
                    match update_client.as_ref().map(UpdateClientHandle::trigger) {
                        Some(ManualTriggerResult::Queued)
                        | Some(ManualTriggerResult::AlreadyQueued)
                        | Some(ManualTriggerResult::AlreadyRunning) => {
                            last_manual_update = Some(Instant::now());
                        }
                        Some(ManualTriggerResult::Stopped) | None => {
                            snapshot.definitions = ServiceDefinitionHealth::Failed {
                                detail: "the authenticated update client is not configured"
                                    .to_owned(),
                            };
                            changed = true;
                        }
                    }
                }
            }

            if last_vault_purge.elapsed() >= VAULT_PURGE_INTERVAL {
                last_vault_purge = Instant::now();
                if let Some(vault) = crate::rollback::global() {
                    vault.purge_expired();
                }
            }

            if last_settings_check.elapsed() >= SETTINGS_CHECK_INTERVAL {
                changed |= reload_settings_if_changed(
                    &settings_path,
                    &settings,
                    &history,
                    &mut observed_settings_stamp,
                    &mut snapshot,
                );
                last_settings_check = Instant::now();
            }

            snapshot.external_rules_suppressed = engine
                .read()
                .map(|active| active.external_rules_tripped())
                .unwrap_or(true);

            let driver_health = protection.driver_health().ok();
            if last_version_refresh
                .is_none_or(|checked| checked.elapsed() >= Duration::from_secs(30))
            {
                snapshot.definition_database_version = active_freshclam
                    .as_ref()
                    .map(|active| active.version.clone());
                last_version_refresh = Some(Instant::now());
            }
            let self_test_ready =
                active_freshclam.is_some() && (!tier.requires_driver() || driver_health.is_some());
            if !self_test_passed
                && self_test_ready
                && last_self_test_attempt
                    .is_none_or(|attempt| attempt.elapsed() >= Duration::from_secs(30))
            {
                last_self_test_attempt = Some(Instant::now());
                let outcome = match engine.read() {
                    Ok(active) => crate::self_test::run_tiered_self_test(tier, &active),
                    Err(_) => Err("the detection engine lock is poisoned".to_owned()),
                };
                match outcome {
                    Ok(message) => {
                        log::info!("{message}");
                        self_test_passed = true;
                    }
                    Err(error) => log::warn!("Protection self-test failed: {error}"),
                }
            }
            let mut components = crate::readiness::ProtectionComponents {
                tier,
                service_operational: snapshot.lifecycle == ServiceLifecycle::Running,
                settings_loaded: true,
                native_definitions_loaded: !matches!(
                    snapshot.definitions,
                    ServiceDefinitionHealth::Failed { .. }
                ),
                freshclam_loaded: active_freshclam.is_some(),
                freshclam_generation: active_freshclam
                    .as_ref()
                    .map(|active| active.generation)
                    .unwrap_or(0),
                rule_generation: definition_generation.load(std::sync::atomic::Ordering::Acquire),
                driver_connected: snapshot.connection == ServiceConnection::Connected
                    && driver_health.is_some(),
                driver_protocol_validated: driver_health.is_some(),
                driver_ready_generation: driver_health.as_ref().and_then(|health| {
                    (health.ready_generation != 0).then_some(health.ready_generation)
                }),
                quarantine_available: quarantine.list().is_ok(),
                history_available: history.recent(1).is_ok(),
                ipc_available: true,
                self_test_passed,
                consecutive_health_successes,
                consecutive_health_failures,
            };
            let preflight_healthy =
                components.mandatory_failures().is_empty() && !snapshot.external_rules_suppressed;
            if preflight_healthy {
                consecutive_health_failures = 0;
                consecutive_health_successes = consecutive_health_successes.saturating_add(1);
            } else {
                consecutive_health_successes = 0;
                consecutive_health_failures = consecutive_health_failures.saturating_add(1);
            }
            components.consecutive_health_successes = consecutive_health_successes;
            components.consecutive_health_failures = consecutive_health_failures;

            if preflight_healthy
                && consecutive_health_successes >= 3
                && components.driver_ready_generation.is_none()
            {
                let generation = definition_generation.load(std::sync::atomic::Ordering::Acquire);
                if protection.set_ready_generation(generation).is_ok() {
                    components.driver_ready_generation = Some(generation);
                }
            }
            readiness.report_components(&components);

            let current_readiness = readiness.diagnostics().current_state;
            if snapshot.readiness.as_ref() != Some(&current_readiness) {
                snapshot.readiness = Some(current_readiness);
                changed = true;
            }

            if changed || last_health_write.elapsed() >= HEALTH_WRITE_INTERVAL {
                snapshot.updated_at = Utc::now();
                snapshot.counters =
                    counter_snapshot(&counters, &protection, &mut snapshot.last_error);
                write_health_best_effort(&health_path, &snapshot, &history);
                last_health_write = Instant::now();
            }
            if runtime_error.is_some() {
                break;
            }
        }

        readiness.update_state(crate::readiness::ReadinessState::Stopping);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        snapshot.lifecycle = ServiceLifecycle::StopPending;
        snapshot.updated_at = Utc::now();
        snapshot.counters = counter_snapshot(&counters, &protection, &mut snapshot.last_error);
        write_health_best_effort(&health_path, &snapshot, &history);
        let stop_status_error = report_state(BodyState::StopPending).err();

        rpc_server.stop();
        if let Some(client) = update_client.take() {
            client.stop();
        }
        protection.stop();

        readiness.update_state(crate::readiness::ReadinessState::Stopped);
        snapshot.readiness = Some(readiness.diagnostics().current_state);
        snapshot.lifecycle = ServiceLifecycle::Stopped;
        snapshot.connection = ServiceConnection::Stopped;
        snapshot.connection_detail = None;
        snapshot.updated_at = Utc::now();
        snapshot.counters = counter_snapshot(&counters, &protection, &mut snapshot.last_error);
        write_health_best_effort(&health_path, &snapshot, &history);
        if let Some(error) = runtime_error {
            Err(error)
        } else if let Some(error) = stop_status_error {
            Err(error)
        } else {
            report_state(BodyState::Stopped)
        }
    }

    fn start_definition_updater(
        settings: &Arc<RwLock<Settings>>,
        snapshot: &mut ServiceHealthSnapshot,
        history: &EventHistory,
    ) -> (
        Option<UpdateClientHandle>,
        Option<mpsc::Receiver<UpdateEvent>>,
    ) {
        let Some(manifest_url) = UPDATE_MANIFEST_URL else {
            return (None, None);
        };
        let key = match configured_trusted_public_key() {
            Ok(Some(key)) => key,
            Ok(None) => {
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: "the build has an update URL but no trusted definition key".to_owned(),
                };
                return (None, None);
            }
            Err(error) => {
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: error.clone(),
                };
                append_error(history, &error);
                return (None, None);
            }
        };
        let store = match DefinitionStore::program_data() {
            Ok(store) => store,
            Err(error) => {
                let detail = format!("definition update store could not be opened: {error}");
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: detail.clone(),
                };
                append_error(history, &detail);
                return (None, None);
            }
        };

        let interval_hours = settings
            .read()
            .map(|value| value.definition_update_interval_hours.clamp(1, 24))
            .unwrap_or(4);
        let interval = Duration::from_secs(interval_hours * 60 * 60);
        let mut config = UpdateClientConfig::new(manifest_url);
        config.scheduler = UpdateScheduler {
            interval,
            maximum_jitter: Duration::from_secs(15 * 60).min(interval / 4),
        };
        if let Some(origins) = UPDATE_ALLOWED_ORIGINS {
            config.allowed_payload_origins = origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect();
        }

        match start_update_client(config, store, key) {
            Ok((client, receiver)) => (Some(client), Some(receiver)),
            Err(error) => {
                let detail = format!("definition updater could not start: {error}");
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: detail.clone(),
                };
                append_error(history, &detail);
                (None, None)
            }
        }
    }

    fn apply_update_event(
        snapshot: &mut ServiceHealthSnapshot,
        stable_definitions: &mut ServiceDefinitionHealth,
        event: UpdateEvent,
        engine: &SharedDetectionEngine,
        history: &EventHistory,
        definition_generation: &Arc<std::sync::atomic::AtomicU64>,
    ) -> bool {
        match event {
            UpdateEvent::CheckStarted { .. } => {
                snapshot.definitions = ServiceDefinitionHealth::Updating {
                    current_version: definition_version(stable_definitions),
                };
            }
            UpdateEvent::Installed { .. } => match load_detection_engine(snapshot, history) {
                Ok(updated) => {
                    replace_detection_engine(engine, updated);
                    definition_generation.fetch_add(1, std::sync::atomic::Ordering::Release);
                    *stable_definitions = snapshot.definitions.clone();
                }
                Err(error) => {
                    snapshot.definitions = ServiceDefinitionHealth::Failed {
                        detail: error.clone(),
                    };
                    append_error(history, &error);
                }
            },
            UpdateEvent::Current { .. } => {
                snapshot.definitions = stable_definitions.clone();
            }
            UpdateEvent::Failed { message, .. } => {
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: message.clone(),
                };
                append_error(history, &message);
            }
            UpdateEvent::Scheduled { .. } | UpdateEvent::Stopped => {}
        }
        true
    }

    fn definition_version(definitions: &ServiceDefinitionHealth) -> Option<String> {
        match definitions {
            ServiceDefinitionHealth::BuiltIn { version }
            | ServiceDefinitionHealth::Current { version, .. }
            | ServiceDefinitionHealth::LastKnownGood { version, .. } => Some(version.clone()),
            ServiceDefinitionHealth::Updating { current_version } => current_version.clone(),
            ServiceDefinitionHealth::Failed { .. } => None,
        }
    }

    fn definitions_expired(definitions: &ServiceDefinitionHealth, now: DateTime<Utc>) -> bool {
        matches!(
            definitions,
            ServiceDefinitionHealth::Current { expires_at, .. }
                | ServiceDefinitionHealth::LastKnownGood { expires_at, .. }
                if *expires_at <= now
        )
    }

    fn load_detection_engine(
        snapshot: &mut ServiceHealthSnapshot,
        history: &EventHistory,
    ) -> Result<DetectionEngine, String> {
        let trusted_key = match configured_trusted_public_key() {
            Ok(Some(key)) => key,
            Ok(None) => {
                snapshot.definitions = ServiceDefinitionHealth::BuiltIn {
                    version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
                };
                return DetectionEngine::builtin();
            }
            Err(error) => {
                snapshot.definitions = ServiceDefinitionHealth::Failed {
                    detail: error.clone(),
                };
                return Err(error);
            }
        };

        let store = DefinitionStore::program_data()
            .map_err(|error| format!("definition store could not be opened: {error}"))?;
        let outcome = store
            .load_with_defaults(Utc::now(), &trusted_key)
            .map_err(|error| format!("definitions could not be loaded: {error}"))?;
        for issue in &outcome.issues {
            append_error(
                history,
                &format!(
                    "Definition {:?} {:?}: {}",
                    issue.candidate, issue.stage, issue.message
                ),
            );
        }
        snapshot.definitions = match outcome.source {
            DefinitionSource::BuiltIn => ServiceDefinitionHealth::BuiltIn {
                version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
            },
            DefinitionSource::Current {
                version,
                bundle_id,
                expires_at,
                ..
            } => ServiceDefinitionHealth::Current {
                version,
                bundle_id,
                expires_at,
            },
            DefinitionSource::LastKnownGood {
                version,
                bundle_id,
                expires_at,
                ..
            } => ServiceDefinitionHealth::LastKnownGood {
                version,
                bundle_id,
                expires_at,
            },
        };
        Ok(outcome.engine)
    }

    fn load_native_index(
        active: &crate::clamdb::downloader::ActiveDatabase,
    ) -> Result<crate::clamdb::native_index::NativeIndex, String> {
        let mut index = crate::clamdb::native_index::NativeIndex::new();
        let loaded = index
            .load_from_directory(
                &active.unpacked_path,
                crate::clamdb::native_index::LoadOptions::default(),
            )
            .map_err(|error| error.to_string())?;
        log::info!(
            "Loaded {} file hashes, {} PE section hashes and {} allowlist entries for generation {}",
            loaded.file_hashes,
            loaded.section_hashes,
            loaded.allowlist_entries,
            active.generation
        );
        Ok(index)
    }

    fn apply_realtime_event(snapshot: &mut ServiceHealthSnapshot, event: RealtimeEvent) -> bool {
        match event {
            RealtimeEvent::Connection(connection) => {
                let (state, detail) = match connection {
                    ProtectionConnection::Connecting => (ServiceConnection::Connecting, None),
                    ProtectionConnection::Connected => (ServiceConnection::Connected, None),
                    ProtectionConnection::Disconnected(error) => {
                        (ServiceConnection::Disconnected, Some(error))
                    }
                    ProtectionConnection::Stopped => (ServiceConnection::Stopped, None),
                };
                snapshot.connection = state;
                snapshot.connection_detail = detail.clone();
                if state == ServiceConnection::Disconnected {
                    snapshot.last_error = detail;
                }
                true
            }
            RealtimeEvent::Decision(decision) => {
                match decision.report.verdict {
                    DetectionVerdict::Malicious | DetectionVerdict::Suspicious => {
                        snapshot.last_detection_at = Some(Utc::now());
                    }
                    DetectionVerdict::Error => {
                        snapshot.last_error = decision.report.error.clone();
                    }
                    DetectionVerdict::Clean => {}
                }
                if let Some(error) = decision.action_error {
                    snapshot.last_error = Some(error);
                }
                true
            }
            RealtimeEvent::QueueSaturated { path, .. } => {
                snapshot.last_error = Some(format!(
                    "real-time scan queue saturated while opening {}",
                    path.display()
                ));
                true
            }
        }
    }

    fn counter_snapshot(
        counters: &Arc<Mutex<RealtimeCounters>>,
        protection: &RealtimeProtection,
        last_error: &mut Option<String>,
    ) -> ServiceCounters {
        let mut snapshot = match counters.lock() {
            Ok(value) => ServiceCounters {
                scanned: value.scanned,
                suspicious: value.suspicious,
                detected: value.detected,
                blocked_replies: value.blocked_replies,
                quarantined: value.quarantined,
                scan_errors: value.scan_errors,
                bypassed_due_to_load: value.bypassed_due_to_load,
                ..ServiceCounters::default()
            },
            Err(_) => {
                *last_error = Some("real-time counter lock was poisoned".to_owned());
                ServiceCounters::default()
            }
        };
        if let Ok(driver) = protection.driver_health() {
            snapshot.driver_scan_requests = driver.scan_requests;
            snapshot.driver_blocks = driver.blocks;
            snapshot.driver_timeouts = driver.timeouts;
            snapshot.service_unavailable_bypasses = driver.service_unavailable_bypasses;
            snapshot.object_resolution_bypasses = driver.object_resolution_bypasses;
            snapshot.oversize_path_bypasses = driver.oversize_path_bypasses;
            snapshot.irql_bypasses = driver.irql_bypasses;
            snapshot.invalid_driver_replies = driver.invalid_replies;
            snapshot.dirty_writes = driver.dirty_writes;
            snapshot.enforcement_bypasses = driver.enforcement_bypasses;
            snapshot.content_race_blocks = driver.content_race_blocks;
            snapshot.path_resolution_failures = driver.path_resolution_failures;
            snapshot.driver_protocol_mismatches = driver.protocol_mismatches;
            snapshot.driver_cache_allows = driver.cache_allows;
            snapshot.driver_boot_policy_allows = driver.boot_policy_allows;
            snapshot.required_enforcement_blocks = driver.required_enforcement_blocks;
            snapshot.driver_queue_overloads = driver.queue_overloads;
            snapshot.driver_ready_generation = driver.ready_generation;
        }
        snapshot
    }

    fn settings_stamp(path: &Path) -> Option<SettingsStamp> {
        fs::metadata(path).ok().map(|metadata| SettingsStamp {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    fn reload_settings_if_changed(
        path: &Path,
        settings: &Arc<RwLock<Settings>>,
        history: &EventHistory,
        observed_stamp: &mut Option<SettingsStamp>,
        snapshot: &mut ServiceHealthSnapshot,
    ) -> bool {
        let current_stamp = settings_stamp(path);
        if current_stamp == *observed_stamp {
            return false;
        }
        *observed_stamp = current_stamp;

        match Settings::load(path) {
            Ok(updated) => {
                snapshot.real_time_enabled = updated.real_time_protection;
                match settings.write() {
                    Ok(mut active) => {
                        *active = updated;
                        true
                    }
                    Err(_) => {
                        snapshot.last_error = Some("settings lock was poisoned".to_owned());
                        true
                    }
                }
            }
            Err(error) => {
                let message =
                    format!("Settings reload failed; previous settings remain active: {error}");
                snapshot.last_error = Some(message.clone());
                append_error(history, &message);
                true
            }
        }
    }

    fn write_health_best_effort(
        path: &Path,
        snapshot: &ServiceHealthSnapshot,
        history: &EventHistory,
    ) {
        match write_service_health_atomic(path, snapshot) {
            Ok(()) => {
                HEALTH_WRITE_ERROR_REPORTED.store(false, Ordering::Release);
            }
            Err(error) => {
                if !HEALTH_WRITE_ERROR_REPORTED.swap(true, Ordering::AcqRel) {
                    append_error(
                        history,
                        &format!("Could not publish the service health snapshot: {error}"),
                    );
                }
            }
        }
    }

    fn append_error(history: &EventHistory, message: &str) {
        let mut event = SecurityEvent::new(EventKind::Error, message);
        event.details = Some(message.to_owned());
        let _ = history.append(&event);
    }

    fn append_service_error(message: String) {
        let history = EventHistory::default_for_machine();
        append_error(&history, &message);
    }

    fn apply_process_self_defense() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{SetKernelObjectSecurity, DACL_SECURITY_INFORMATION};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;0x121411;;;BA)\0"
            .encode_utf16()
            .collect();
        let mut descriptor = std::ptr::null_mut();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                log::warn!(
                    "Could not build the service's process DACL: {}",
                    std::io::Error::last_os_error()
                );
                return;
            }
            let applied =
                SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, descriptor);
            // Read before LocalFree, which can overwrite the thread's last error.
            let error = std::io::Error::last_os_error();
            LocalFree(descriptor);
            if applied != 0 {
                log::info!("Applied hardened process DACL self-defense to service");
            } else {
                log::warn!("Could not apply the service's process DACL: {error}");
            }
        }
    }
}

#[cfg(windows)]
#[allow(unused_imports)]
pub use windows_service_host::{run_service_body, run_service_console, run_service_dispatcher};

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot(now: DateTime<Utc>, lifecycle: ServiceLifecycle) -> ServiceHealthSnapshot {
        let mut snapshot = ServiceHealthSnapshot::starting(now, true);
        snapshot.lifecycle = lifecycle;
        snapshot
    }

    #[test]
    fn health_path_is_stable_and_machine_scoped() {
        let path = service_health_path_from_program_data(Path::new(r"D:\MachineData"));
        assert_eq!(
            path,
            PathBuf::from(r"D:\MachineData\blackshard\service-health.json")
        );
    }

    #[test]
    fn health_snapshot_is_atomically_replaced_and_readable() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join("state")
            .join(SERVICE_HEALTH_FILE_NAME);
        let now = Utc::now();

        let first = test_snapshot(now, ServiceLifecycle::StartPending);
        write_service_health_atomic(&path, &first).unwrap();
        assert_eq!(read_service_health(&path).unwrap(), first);

        let mut second = test_snapshot(now, ServiceLifecycle::Running);
        second.connection = ServiceConnection::Connected;
        second.counters.scanned = 42;
        write_service_health_atomic(&path, &second).unwrap();
        assert_eq!(read_service_health(&path).unwrap(), second);

        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
