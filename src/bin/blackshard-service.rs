use blackshard::*;

use chrono::Utc;

use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::sync::Arc;

const SERVICE_ARGUMENT: &str = "--service";
const SERVICE_CONSOLE_ARGUMENT: &str = "--service-console";
const SELF_TEST_ARGUMENT: &str = "--blackshard-self-test-open";
const INSTALL_DRIVER_ARGUMENT: &str = "--install-driver";
const UNINSTALL_DRIVER_ARGUMENT: &str = "--uninstall-driver";
const NOTIFICATION_AGENT_ARGUMENT: &str = "--notification-agent";
const UPDATE_DEFINITIONS_ARGUMENT: &str = "--update-definitions";
const VALIDATE_RELEASE_CONFIGURATION_ARGUMENT: &str = "--validate-release-configuration";
const VALIDATE_DEFINITION_PAYLOAD_ARGUMENT: &str = "--validate-definition-payload";
const VERIFY_DEFINITION_UPDATE_ARGUMENT: &str = "--verify-definition-update";
const EVALUATE_CORPUS_ARGUMENT: &str = "--evaluate-corpus";

fn requested_mode() -> Option<String> {
    std::env::args().nth(1)
}

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

fn definition_payload_validation_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(VALIDATE_DEFINITION_PAYLOAD_ARGUMENT)) {
        return None;
    }
    let Some(payload_path) = arguments.next() else {
        return Some(2);
    };
    if arguments.next().is_some() {
        return Some(2);
    }
    let result = read_validation_file(
        std::path::Path::new(&payload_path),
        definitions::MAX_DEFINITION_PAYLOAD_BYTES as u64,
    )
    .and_then(|payload| {
        definitions::DefinitionPayload::from_bytes(&payload).map_err(|error| error.to_string())
    });
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
    /// What scored, for anything not clean: `code (points): description`.
    reasons: Vec<String>,
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
    // Optionally the unpacked ClamAV databases to evaluate with, as `--update-definitions` reports.
    let signatures = arguments.next();
    if arguments.next().is_some() {
        return Some(2);
    }
    Some(
        match evaluate_corpus(
            std::path::Path::new(&root),
            std::path::Path::new(&output),
            signatures.as_deref().map(std::path::Path::new),
        ) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("corpus evaluation failed: {error}");
                1
            }
        },
    )
}

/// How fast the signature matcher alone reads the corpus, apart from everything else a scan does,
/// so a slowdown can be told from a slower matcher.
fn report_matcher_speed(index: &clamdb::native_index::NativeIndex, root: &std::path::Path) {
    use std::io::Read;
    const SAMPLE_BYTES: u64 = 64 * 1024 * 1024;
    let (mut bytes_read, mut files, mut hits) = (0u64, 0usize, 0usize);
    let mut elapsed = std::time::Duration::ZERO;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .max_depth(64)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        let Ok(file) = fs::File::open(entry.path()) else {
            continue;
        };
        let size = file.metadata().map_or(0, |metadata| metadata.len());
        let mut sample = Vec::new();
        if file.take(SAMPLE_BYTES).read_to_end(&mut sample).is_err() {
            continue;
        }
        let started = std::time::Instant::now();
        if index
            .evaluate_patterns(&sample, size, &[0; 32], None)
            .is_some()
        {
            hits += 1;
        }
        elapsed += started.elapsed();
        bytes_read += sample.len() as u64;
        files += 1;
    }
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    let (anchors, checks) = index.pattern_work();
    let mib = bytes_read as f64 / (1024.0 * 1024.0);
    println!(
        "Signature matcher alone: {:.1} MiB/s over {files} files ({hits} matched); {:.0} anchor hits and {:.0} full checks per MiB",
        mib / seconds,
        anchors as f64 / mib.max(f64::EPSILON),
        checks as f64 / mib.max(f64::EPSILON)
    );
}

fn evaluate_corpus(
    root: &std::path::Path,
    output: &std::path::Path,
    signatures: Option<&std::path::Path>,
) -> Result<(), String> {
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

    let mut engine = detection::DetectionEngine::builtin()?;
    if let Some(signatures) = signatures {
        let mut index = clamdb::native_index::NativeIndex::new();
        let loaded = index
            .load_from_directory(signatures, clamdb::native_index::LoadOptions::default())
            .map_err(|error| error.to_string())?;
        println!(
            "Evaluating with {} file hashes, {} section hashes and {} body signatures",
            loaded.file_hashes, loaded.section_hashes, loaded.patterns
        );
        report_matcher_speed(&index, &root);
        engine = engine.with_native_index(index);
    }
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
            reasons: if verdict == "clean" {
                Vec::new()
            } else {
                report
                    .static_report
                    .iter()
                    .flat_map(|stat| stat.evidence.iter())
                    .filter(|item| item.risk_points > 0)
                    .map(|item| {
                        format!("{} ({}): {}", item.code, item.risk_points, item.description)
                    })
                    .chain(
                        report
                            .rule_matches
                            .iter()
                            .map(|rule| format!("rule {} ({})", rule.threat_name, rule.risk_score)),
                    )
                    .collect()
            },
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

fn run_service_mode() -> Result<(), Box<dyn Error>> {
    service::run_service_dispatcher()?;
    Ok(())
}

fn run_service_console_mode() -> Result<(), Box<dyn Error>> {
    use std::sync::atomic::AtomicBool;

    let stop = Arc::new(AtomicBool::new(false));
    service::run_service_console(stop).map_err(Into::into)
}

fn driver_change_exit_code(install: bool) -> i32 {
    let mut arguments = std::env::args_os();
    arguments.next();
    arguments.next();
    let Some(inf_path) = arguments.next() else {
        return 2;
    };
    if arguments.next().is_some() {
        return 2;
    }

    let result = if install {
        driver_installer::install_driver(std::path::Path::new(&inf_path))
    } else {
        driver_installer::uninstall_driver(std::path::Path::new(&inf_path))
    };
    match result {
        Ok(driver_installer::DriverChange::Complete) => 0,
        Ok(driver_installer::DriverChange::RebootRequired) => {
            driver_installer::REBOOT_REQUIRED_EXIT_CODE
        }
        Err(_error) => 1,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    if requested_mode().as_deref() == Some(SERVICE_ARGUMENT) {
        // Started by the service control manager: there is no console, so stderr goes nowhere.
        service_log::init(service_log::default_path())?;
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    if let Some(exit_code) = self_test_probe_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = elevation::elevated_action_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = release_configuration_validation_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = definition_payload_validation_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = definition_update_verification_exit_code() {
        std::process::exit(exit_code);
    }
    if let Some(exit_code) = corpus_evaluation_exit_code() {
        std::process::exit(exit_code);
    }

    match requested_mode().as_deref() {
        Some(SERVICE_ARGUMENT) => run_service_mode(),
        Some(SERVICE_CONSOLE_ARGUMENT) => run_service_console_mode(),
        Some(INSTALL_DRIVER_ARGUMENT) => std::process::exit(driver_change_exit_code(true)),
        Some(UNINSTALL_DRIVER_ARGUMENT) => std::process::exit(driver_change_exit_code(false)),
        Some(NOTIFICATION_AGENT_ARGUMENT) => notification_agent::run().map_err(Into::into),
        Some(UPDATE_DEFINITIONS_ARGUMENT) => {
            let destination = std::env::args_os()
                .nth(2)
                .map(std::path::PathBuf::from)
                .ok_or("usage: blackshard-service --update-definitions <blackshard data path>")?;
            let active = clamdb::downloader::download_databases(&destination)?;

            // Load the databases straight back so the command fails loudly if a container was
            // fetched and unpacked but turns out to hold nothing blackshard can evaluate.
            let mut index = clamdb::native_index::NativeIndex::new();
            let stats = index.load_from_directory(
                &active.unpacked_path,
                clamdb::native_index::LoadOptions::default(),
            )?;
            println!(
                "Activated definition generation {} version {} at {}",
                active.generation,
                active.version,
                active.path.display()
            );
            println!(
                "Indexed {} file hashes, {} PE section hashes and {} allowlist entries",
                stats.file_hashes, stats.section_hashes, stats.allowlist_entries
            );
            println!(
                "Indexed {} body and logical signatures; skipped {} that use features not yet modelled or are too weak",
                stats.patterns, stats.patterns_skipped
            );
            let mut reasons: Vec<_> = stats.pattern_skip_reasons.iter().collect();
            reasons.sort_by(|left, right| right.1.cmp(left.1));
            for (reason, count) in reasons {
                println!("  skipped {count:>7}  {reason}");
            }
            println!("Unpacked databases at {}", active.unpacked_path.display());
            if stats.file_hashes == 0 {
                return Err("the activated generation produced no usable file hashes".into());
            }
            Ok(())
        }
        _ => Err("UI mode is not supported in this build".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::path::Path;

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
