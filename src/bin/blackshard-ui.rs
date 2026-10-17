// A GUI program: started from the Start menu it used to open a console window beside itself.
// Tests keep the console subsystem so their output is visible.
#![cfg_attr(not(test), windows_subsystem = "windows")]

use blackshard::*;

use blackshard::ipc::IpcClient;
use blackshard::service::{
    default_service_health_path, read_service_health, ServiceConnection, ServiceDefinitionHealth,
    ServiceHealthSnapshot, ServiceLifecycle, SERVICE_HEALTH_SCHEMA_VERSION,
};
use blackshard::ui::{
    complete_protection_test, new_shared_ui_state, take_protection_test_request, BlackshardApp,
    BuildTrustStatus, CertificationStatus, DefinitionStatus, DriverStatus, ProtectionStatus,
    SharedUiState,
};
use chrono::Utc;
use eframe::egui;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SELF_TEST_ARGUMENT: &str = "--blackshard-self-test-open";
const VALIDATE_RELEASE_CONFIGURATION_ARGUMENT: &str = "--validate-release-configuration";
const VERIFY_DEFINITION_UPDATE_ARGUMENT: &str = "--verify-definition-update";
const EVALUATE_CORPUS_ARGUMENT: &str = "--evaluate-corpus";
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HEALTH_STALE_AFTER_SECONDS: i64 = 10;

fn self_test_probe_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(SELF_TEST_ARGUMENT)) {
        return None;
    }

    let Some(path) = arguments.next() else {
        return Some(12);
    };

    Some(match File::open(path) {
        Ok(_) => 0,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => 10,
        Err(_) => 11,
    })
}

fn release_configuration_validation_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(VALIDATE_RELEASE_CONFIGURATION_ARGUMENT)) {
        return None;
    }

    let (Some(inf_path), Some(manifest_url), Some(public_key_hex)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Some(2);
    };
    if arguments.next().is_some() {
        return Some(2);
    }

    let manifest_url = manifest_url.to_string_lossy();
    let public_key_hex = public_key_hex.to_string_lossy();
    let embedded_manifest = option_env!("BLACKSHARD_UPDATE_MANIFEST_URL");
    let embedded_key = option_env!("BLACKSHARD_DEFINITION_PUBLIC_KEY_HEX");
    let public_key_is_valid = hex::decode(public_key_hex.as_ref())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .is_some_and(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_ok());
    let manifest_is_valid = update_client::UpdateClientConfig::new(manifest_url.to_string())
        .validate()
        .is_ok();
    let configuration_matches = embedded_manifest == Some(manifest_url.as_ref())
        && embedded_key.is_some_and(|key| key.eq_ignore_ascii_case(&public_key_hex))
        && public_key_is_valid
        && manifest_is_valid;

    Some(
        if configuration_matches
            && driver_installer::validate_release_inf(std::path::Path::new(&inf_path)).is_ok()
        {
            0
        } else {
            1
        },
    )
}

fn definition_update_verification_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(VERIFY_DEFINITION_UPDATE_ARGUMENT)) {
        return None;
    }
    let (Some(envelope_path), Some(payload_path), Some(public_key_hex)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Some(2);
    };
    if arguments.next().is_some() {
        return Some(2);
    }

    let result = (|| -> Result<(), String> {
        let envelope_bytes = read_validation_file(
            std::path::Path::new(&envelope_path),
            updater::MAX_ENVELOPE_BYTES as u64,
        )?;
        let payload = read_validation_file(
            std::path::Path::new(&payload_path),
            definitions::MAX_DEFINITION_PAYLOAD_BYTES as u64,
        )?;
        let key = hex::decode(public_key_hex.to_string_lossy().as_ref())
            .map_err(|_| "public key is not hexadecimal".to_owned())?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| "public key must contain exactly 32 bytes".to_owned())?;
        let envelope = updater::SignedUpdateEnvelope::from_json(&envelope_bytes)
            .map_err(|error| error.to_string())?;
        let installed_sequence = envelope.manifest.sequence.saturating_sub(1);
        updater::verify_update(
            &envelope,
            &payload,
            installed_sequence,
            Utc::now(),
            definitions::MAX_DEFINITION_PAYLOAD_BYTES as u64,
            &key,
        )
        .map_err(|error| error.to_string())?;
        definitions::DefinitionPayload::from_bytes(&payload).map_err(|error| error.to_string())?;
        Ok(())
    })();
    Some(if result.is_ok() { 0 } else { 1 })
}

#[derive(serde::Serialize)]
struct CorpusFileResult {
    path: String,
    verdict: String,
    risk_score: u8,
    confidence: u8,
    threat_name: Option<String>,
    sha256: Option<String>,
    file_size: u64,
    elapsed_micros: u64,
    container_findings: usize,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct CorpusReport {
    schema_version: u32,
    product_version: &'static str,
    generated_at: chrono::DateTime<Utc>,
    root: String,
    files: usize,
    bytes: u64,
    clean: usize,
    suspicious: usize,
    malicious: usize,
    errors: usize,
    wall_millis: u64,
    throughput_mib_per_second: f64,
    latency_p50_micros: u64,
    latency_p95_micros: u64,
    latency_p99_micros: u64,
    results: Vec<CorpusFileResult>,
}

fn corpus_evaluation_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(EVALUATE_CORPUS_ARGUMENT)) {
        return None;
    }
    let (Some(root), Some(output)) = (arguments.next(), arguments.next()) else {
        return Some(2);
    };
    if arguments.next().is_some() {
        return Some(2);
    }
    Some(
        match evaluate_corpus(std::path::Path::new(&root), std::path::Path::new(&output)) {
            Ok(()) => 0,
            Err(_) => 1,
        },
    )
}

fn evaluate_corpus(root: &std::path::Path, output: &std::path::Path) -> Result<(), String> {
    const MAX_CORPUS_FILES: usize = 100_000;
    const MAX_CORPUS_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if !root.is_dir() {
        return Err("corpus root is not a directory".to_owned());
    }
    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(output)
    };
    if output.starts_with(&root) {
        return Err("corpus report must be written outside the corpus root".to_owned());
    }

    let engine = detection::DetectionEngine::builtin()?;
    let wall_started = std::time::Instant::now();
    let mut results = Vec::new();
    let mut total_bytes = 0u64;
    let (mut clean, mut suspicious, mut malicious, mut errors) = (0, 0, 0, 0);
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .max_depth(64)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if results.len() >= MAX_CORPUS_FILES {
            return Err("corpus exceeds the 100,000-file evaluation limit".to_owned());
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or("corpus byte count overflow")?;
        if total_bytes > MAX_CORPUS_BYTES {
            return Err("corpus exceeds the 1 TiB evaluation limit".to_owned());
        }
        let report = engine.scan_path(entry.path());
        let verdict = match report.verdict {
            detection::DetectionVerdict::Clean => {
                clean += 1;
                "clean"
            }
            detection::DetectionVerdict::Suspicious => {
                suspicious += 1;
                "suspicious"
            }
            detection::DetectionVerdict::Malicious => {
                malicious += 1;
                "malicious"
            }
            detection::DetectionVerdict::Error => {
                errors += 1;
                "error"
            }
        };
        results.push(CorpusFileResult {
            path: entry
                .path()
                .strip_prefix(&root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned(),
            verdict: verdict.to_owned(),
            risk_score: report.risk_score,
            confidence: report.confidence,
            threat_name: report.threat_name,
            sha256: report.sha256,
            file_size: report.file_size,
            elapsed_micros: report.elapsed.as_micros().min(u64::MAX as u128) as u64,
            container_findings: report
                .container_inspection
                .as_ref()
                .map(|inspection| inspection.findings.len())
                .unwrap_or(0),
            error: report.error,
        });
    }
    let wall = wall_started.elapsed();
    let mut latencies = results
        .iter()
        .map(|result| result.elapsed_micros)
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    let percentile = |percent: usize| -> u64 {
        if latencies.is_empty() {
            return 0;
        }
        let index = (latencies.len() - 1).saturating_mul(percent) / 100;
        latencies[index]
    };
    let seconds = wall.as_secs_f64();
    let report = CorpusReport {
        schema_version: 1,
        product_version: env!("CARGO_PKG_VERSION"),
        generated_at: Utc::now(),
        root: root.to_string_lossy().into_owned(),
        files: results.len(),
        bytes: total_bytes,
        clean,
        suspicious,
        malicious,
        errors,
        wall_millis: wall.as_millis().min(u64::MAX as u128) as u64,
        throughput_mib_per_second: if seconds > 0.0 {
            total_bytes as f64 / (1024.0 * 1024.0) / seconds
        } else {
            0.0
        },
        latency_p50_micros: percentile(50),
        latency_p95_micros: percentile(95),
        latency_p99_micros: percentile(99),
        results,
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    atomic_file::write(&output, &bytes).map_err(|error| error.to_string())
}

fn read_validation_file(path: &std::path::Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!(
            "validation input is not a bounded regular file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.len() as u64 > maximum {
        return Err("validation input grew beyond its limit".to_owned());
    }
    Ok(bytes)
}

fn apply_service_health(runtime: &SharedUiState, health: ServiceHealthSnapshot) {
    let mut state = match runtime.lock() {
        Ok(state) => state,
        Err(_) => return,
    };

    if health.schema_version != SERVICE_HEALTH_SCHEMA_VERSION {
        let detail = format!(
            "unsupported service health schema {}",
            health.schema_version
        );
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
        return;
    }

    let age = Utc::now().signed_duration_since(health.updated_at);
    if age.num_seconds() > HEALTH_STALE_AFTER_SECONDS || age.num_seconds() < -30 {
        let detail = format!(
            "the protection service health timestamp is outside the trusted window ({})",
            age.num_seconds(),
        );
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
        return;
    }

    state.engine_version = health.product_version;
    state.realtime_scanned_files = health.counters.scanned;
    state.realtime_blocked_files = health.counters.blocked_replies;
    state.realtime_bypassed_requests = health
        .counters
        .bypassed_due_to_load
        .saturating_add(health.counters.driver_timeouts)
        .saturating_add(health.counters.service_unavailable_bypasses)
        .saturating_add(health.counters.object_resolution_bypasses)
        .saturating_add(health.counters.oversize_path_bypasses)
        .saturating_add(health.counters.irql_bypasses)
        .saturating_add(health.counters.enforcement_bypasses);
    state.definitions = match health.definitions {
        ServiceDefinitionHealth::BuiltIn { version } => DefinitionStatus::BuiltInOnly { version },
        ServiceDefinitionHealth::Updating { current_version } => {
            DefinitionStatus::Updating { current_version }
        }
        ServiceDefinitionHealth::Current {
            version,
            expires_at,
            ..
        }
        | ServiceDefinitionHealth::LastKnownGood {
            version,
            expires_at,
            ..
        } if expires_at > Utc::now() => DefinitionStatus::Current {
            version,
            expires_at,
        },
        ServiceDefinitionHealth::Current {
            version,
            expires_at,
            ..
        }
        | ServiceDefinitionHealth::LastKnownGood {
            version,
            expires_at,
            ..
        } => DefinitionStatus::Stale {
            version,
            expired_at: expires_at,
        },
        ServiceDefinitionHealth::Failed { detail } => DefinitionStatus::Failed(detail),
    };
    state.tier = health.tier;
    state.driver = match (health.tier, &health.connection) {
        // With no driver installed the service never opens the port, so the connection state is
        // meaningless here and would otherwise sit on "Checking" forever.
        (blackshard::readiness::ProtectionTier::Userland, _) => DriverStatus::NotRequired,
        (_, ServiceConnection::Connecting) => DriverStatus::Checking,
        (_, ServiceConnection::Connected) => DriverStatus::Connected,
        (_, ServiceConnection::Disconnected) => DriverStatus::Disconnected(
            health
                .connection_detail
                .clone()
                .unwrap_or_else(|| "the minifilter channel is disconnected".to_owned()),
        ),
        (_, ServiceConnection::Stopped) => {
            DriverStatus::Disconnected("the protection service is stopped".to_owned())
        }
    };

    state.protection = match health.lifecycle {
        ServiceLifecycle::StartPending => ProtectionStatus::Starting,
        ServiceLifecycle::StopPending | ServiceLifecycle::Stopped => {
            ProtectionStatus::Unavailable("the protection service is stopped".to_owned())
        }
        ServiceLifecycle::Running if !health.real_time_enabled => ProtectionStatus::Paused,
        ServiceLifecycle::Running if health.external_rules_suppressed => {
            ProtectionStatus::Degraded(
                "external rule matches exceeded the safety threshold and were suppressed"
                    .to_owned(),
            )
        }
        // Readiness already accounts for the tier, so a userland install that reached Ready is
        // genuinely active; requiring a kernel connection here would have contradicted it.
        ServiceLifecycle::Running
            if matches!(health.readiness, Some(readiness::ReadinessState::Ready))
                && (health.tier == readiness::ProtectionTier::Userland
                    || health.connection == ServiceConnection::Connected) =>
        {
            ProtectionStatus::Active
        }
        ServiceLifecycle::Running => ProtectionStatus::Degraded(
            health
                .connection_detail
                .clone()
                .or(health.last_error.clone())
                .unwrap_or_else(|| "the kernel minifilter is not connected".to_owned()),
        ),
    };

    state.attention = match &state.protection {
        ProtectionStatus::Active | ProtectionStatus::Paused | ProtectionStatus::Starting => None,
        ProtectionStatus::Degraded(detail) | ProtectionStatus::Unavailable(detail) => {
            Some(detail.clone())
        }
    };
}

fn set_health_read_error(runtime: &SharedUiState, error: &io::Error) {
    let mut state = match runtime.lock() {
        Ok(state) => state,
        Err(_) => return,
    };

    if error.kind() == io::ErrorKind::NotFound {
        let detail = "the protection service is not running. If blackshard was just installed, \
                      give it a few seconds; otherwise restart the computer or reinstall blackshard.";
        state.driver = DriverStatus::NotInstalled;
        state.protection = ProtectionStatus::Unavailable(detail.to_owned());
        state.attention = None;
    } else {
        let detail = format!("could not read protection-service health: {error}");
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
    }
}

fn start_service_health_monitor(runtime: SharedUiState) {
    let path = default_service_health_path();
    let read_health = move |runtime: &SharedUiState| match read_service_health(&path) {
        Ok(health) => apply_service_health(runtime, health),
        Err(error) => set_health_read_error(runtime, &error),
    };
    // Once before the window exists, so the app knows whether the service is up before it
    // tries to talk to it.
    read_health(&runtime);
    thread::spawn(move || loop {
        thread::sleep(HEALTH_POLL_INTERVAL);
        read_health(&runtime);
        if take_protection_test_request(&runtime) {
            let test_runtime = Arc::clone(&runtime);
            thread::spawn(move || {
                complete_protection_test(&test_runtime, run_harmless_protection_test());
            });
        }
        process_update_request(&runtime);
    });
}

fn process_update_request(runtime: &SharedUiState) {
    let requested = match runtime.lock() {
        Ok(mut state) if state.update_check_requested => {
            state.update_check_requested = false;
            true
        }
        _ => false,
    };
    if !requested {
        return;
    }

    match IpcClient.request_update() {
        Ok(_) => {
            if let Ok(mut state) = runtime.lock() {
                let current_version = match &state.definitions {
                    DefinitionStatus::BuiltInOnly { version }
                    | DefinitionStatus::Current { version, .. }
                    | DefinitionStatus::Stale { version, .. } => Some(version.clone()),
                    DefinitionStatus::Updating { current_version } => current_version.clone(),
                    DefinitionStatus::Failed(_) => None,
                };
                state.definitions = DefinitionStatus::Updating { current_version };
            }
        }
        Err(error) => {
            if let Ok(mut state) = runtime.lock() {
                state.definitions = DefinitionStatus::Failed(format!(
                    "could not ask the protection service to update: {error}"
                ));
            }
        }
    }
}

fn run_harmless_protection_test() -> Result<String, String> {
    let path = std::env::temp_dir().join(format!(
        "blackshard-harmless-test-{}.com",
        std::process::id()
    ));
    fs::write(&path, self_test::PAYLOAD)
        .map_err(|error| format!("could not create the harmless test file: {error}"))?;

    let result = std::env::current_exe()
        .map_err(|error| format!("could not locate the blackshard executable: {error}"))
        .and_then(|executable| {
            realtime::launch_hidden_probe(&executable, SELF_TEST_ARGUMENT, &path)
                .map_err(|error| format!("could not launch the isolated test probe: {error}"))
        });
    let _ = fs::remove_file(&path);

    match result {
        Ok(10) => Ok("The minifilter denied the inert test signature end to end.".to_owned()),
        Ok(0) => Err(
            "the inert test signature was opened; real-time enforcement did not block it"
                .to_owned(),
        ),
        Ok(code) => Err(format!(
            "the protection-test probe exited unexpectedly ({code})"
        )),
        Err(error) => Err(error),
    }
}

fn initialize_runtime(runtime: &SharedUiState) {
    if let Ok(mut state) = runtime.lock() {
        state.build_trust = BuildTrustStatus::Checking;
        state.certification = CertificationStatus::NotEvaluated;
        state.definitions = DefinitionStatus::BuiltInOnly {
            version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
        };
    }

    let trust_runtime = Arc::clone(runtime);
    thread::spawn(move || {
        let trust = match trust::verify_current_executable() {
            trust::AuthenticodeStatus::Trusted { publisher } => {
                BuildTrustStatus::AuthenticodeVerified { publisher }
            }
            trust::AuthenticodeStatus::Unsigned => BuildTrustStatus::UnsignedDevelopmentBuild,
            trust::AuthenticodeStatus::Untrusted(error)
            | trust::AuthenticodeStatus::Error(error) => {
                BuildTrustStatus::VerificationFailed(error)
            }
        };
        if let Ok(mut state) = trust_runtime.lock() {
            state.build_trust = trust;
        }
    });
}

fn run_ui() -> Result<(), Box<dyn Error>> {
    let runtime = new_shared_ui_state();
    initialize_runtime(&runtime);
    start_service_health_monitor(Arc::clone(&runtime));

    let mut wgpu_setup = eframe::egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    wgpu_setup.instance_descriptor.backends = eframe::wgpu::Backends::DX12;
    wgpu_setup.power_preference = eframe::wgpu::PowerPreference::LowPower;
    let wgpu_options = eframe::egui_wgpu::WgpuConfiguration {
        wgpu_setup: eframe::egui_wgpu::WgpuSetup::CreateNew(wgpu_setup),
        ..Default::default()
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([920.0, 600.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../../assets/icon-256.png"))
                    .unwrap_or_default(),
            ),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        ..Default::default()
    };

    eframe::run_native(
        "blackshard",
        options,
        Box::new(move |creation_context| {
            BlackshardApp::apply_theme(&creation_context.egui_ctx);
            Ok(Box::new(BlackshardApp::with_machine_defaults(runtime)))
        }),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some(
            VALIDATE_RELEASE_CONFIGURATION_ARGUMENT
                | VERIFY_DEFINITION_UPDATE_ARGUMENT
                | EVALUATE_CORPUS_ARGUMENT
        )
    ) {
        attach_parent_console();
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Some(exit_code) = self_test_probe_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = elevation::elevated_action_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = release_configuration_validation_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = definition_update_verification_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = corpus_evaluation_exit_code() {
        std::process::exit(exit_code);
    }
    run_ui().inspect_err(|error| show_startup_error(&error.to_string()))
}

/// The command-line modes write to the terminal they were started from; a GUI program has no
/// console of its own.
#[cfg(windows)]
fn attach_parent_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    // Fails harmlessly when there is no parent console, as when started from Explorer.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

#[cfg(not(windows))]
fn attach_parent_console() {}

/// Without a console, a window that fails to open (no usable graphics adapter, say) would leave
/// nothing behind at all.
#[cfg(windows)]
fn show_startup_error(message: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(window: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    const MB_OK_ICONERROR: u32 = 0x0000_0010;
    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let text = wide(&format!(
        "blackshard could not open its window.\n\n{message}"
    ));
    let caption = wide("blackshard");
    unsafe { MessageBoxW(0, text.as_ptr(), caption.as_ptr(), MB_OK_ICONERROR) };
}

#[cfg(not(windows))]
fn show_startup_error(message: &str) {
    eprintln!("blackshard could not open its window: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::path::Path;

    #[test]
    fn health_monitor_requires_a_fresh_connected_running_service() {
        let now = Utc::now();
        let runtime = new_shared_ui_state();
        let health = ServiceHealthSnapshot {
            schema_version: SERVICE_HEALTH_SCHEMA_VERSION,
            product_version: "1.2.3".to_owned(),
            process_id: 42,
            lifecycle: ServiceLifecycle::Running,
            connection: ServiceConnection::Connected,
            connection_detail: None,
            real_time_enabled: true,
            external_rules_suppressed: false,
            started_at: now,
            updated_at: now,
            last_detection_at: None,
            last_error: None,
            readiness: Some(readiness::ReadinessState::Ready),
            definitions: ServiceDefinitionHealth::BuiltIn {
                version: "embedded-test".to_owned(),
            },
            counters: service::ServiceCounters::default(),
            definition_database_version: Some("1".to_owned()),
            tier: blackshard::readiness::ProtectionTier::Kernel,
        };

        apply_service_health(&runtime, health);
        let state = runtime.lock().unwrap();
        assert_eq!(state.protection, ProtectionStatus::Active);
        assert_eq!(state.driver, DriverStatus::Connected);
    }

    #[test]
    fn disabled_realtime_is_reported_as_paused_not_active() {
        let now = Utc::now();
        let runtime = new_shared_ui_state();
        let health = ServiceHealthSnapshot {
            schema_version: SERVICE_HEALTH_SCHEMA_VERSION,
            product_version: "1.2.3".to_owned(),
            process_id: 42,
            lifecycle: ServiceLifecycle::Running,
            connection: ServiceConnection::Connected,
            connection_detail: None,
            real_time_enabled: false,
            external_rules_suppressed: false,
            started_at: now,
            updated_at: now,
            last_detection_at: None,
            last_error: None,
            readiness: Some(readiness::ReadinessState::Ready),
            definitions: ServiceDefinitionHealth::BuiltIn {
                version: "embedded-test".to_owned(),
            },
            counters: service::ServiceCounters::default(),
            definition_database_version: Some("1".to_owned()),
            tier: blackshard::readiness::ProtectionTier::Kernel,
        };

        apply_service_health(&runtime, health);
        assert_eq!(runtime.lock().unwrap().protection, ProtectionStatus::Paused);
    }

    #[test]
    fn missing_health_file_never_claims_protection() {
        let runtime = new_shared_ui_state();
        set_health_read_error(
            &runtime,
            &io::Error::new(io::ErrorKind::NotFound, "missing"),
        );
        let state = runtime.lock().unwrap();
        assert_eq!(state.driver, DriverStatus::NotInstalled);
        assert!(matches!(state.protection, ProtectionStatus::Unavailable(_)));
    }

    #[test]
    fn self_test_probe_argument_is_stable() {
        assert_eq!(SELF_TEST_ARGUMENT, "--blackshard-self-test-open");
        assert!(Path::new(SELF_TEST_ARGUMENT).file_name().is_some());
        assert_eq!(self_test::PAYLOAD.len(), 72);
        assert_eq!(
            hex::encode(sha2::Sha256::digest(self_test::PAYLOAD)),
            engine::BLACKSHARD_SELF_TEST_SHA256
        );
    }
}
