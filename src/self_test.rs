use crate::detection::{DetectionEngine, DetectionVerdict};
use crate::readiness::ProtectionTier;
#[cfg(windows)]
use crate::realtime;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use uuid::Uuid;

pub const PAYLOAD: &[u8] =
    b"BLACKSHARD-HARMLESS-SELF-TEST-V2\nThis file contains no executable code.\n";

/// Runs whichever self-test the active protection tier can actually satisfy.
///
/// The kernel tier proves enforcement end to end by having the driver block a real open. Without a
/// driver there is nothing to block the open, so the userland tier proves the next strongest thing
/// available: that the detection engine convicts the payload.
pub fn run_tiered_self_test(
    tier: ProtectionTier,
    engine: &DetectionEngine,
) -> Result<String, String> {
    match tier {
        ProtectionTier::Kernel => run_self_test(),
        ProtectionTier::Userland => run_detection_self_test(engine),
    }
}

/// Confirms the detection engine convicts the harmless self-test payload.
///
/// This exercises the signature path only; it deliberately makes no claim about enforcement, which
/// is what [`run_self_test`] covers when a driver is present.
pub fn run_detection_self_test(engine: &DetectionEngine) -> Result<String, String> {
    let report = engine.scan_bytes(PAYLOAD);
    match report.verdict {
        DetectionVerdict::Malicious => Ok(
            "The detection engine identified the test payload. On-demand and AMSI scanning are active."
                .to_owned(),
        ),
        other => Err(format!(
            "The detection engine returned {other:?} for the self-test payload; definitions may be missing or corrupt."
        )),
    }
}

#[cfg(not(windows))]
pub fn run_self_test() -> Result<String, String> {
    Err("the kernel self-test needs the Windows driver".to_owned())
}

#[cfg(windows)]
pub fn run_self_test() -> Result<String, String> {
    let test_id = Uuid::new_v4();
    let file_name = format!("blackshard-selftest-{}.com", test_id);
    let path = std::env::temp_dir().join(file_name);

    fs::write(&path, PAYLOAD)
        .map_err(|error| format!("could not create the test file: {error}"))?;

    let result = std::env::current_exe()
        .map_err(|error| format!("could not locate the executable: {error}"))
        .and_then(|executable| {
            realtime::launch_hidden_probe(&executable, "--blackshard-self-test-open", &path)
                .map_err(|error| format!("could not launch the isolated test probe: {error}"))
        });

    let _ = fs::remove_file(&path);

    match result {
        Ok(10) => Ok("The real-time protection successfully blocked the test file.".to_owned()),
        Ok(0) => Err(
            "The test file was opened successfully; real-time enforcement did not block it."
                .to_owned(),
        ),
        Ok(code) => Err(format!("The test probe exited unexpectedly ({code})")),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_detection_self_test_convicts_the_payload() {
        let engine = DetectionEngine::builtin().unwrap();
        let message = run_detection_self_test(&engine).unwrap();
        assert!(message.contains("identified the test payload"), "{message}");
    }

    #[test]
    fn the_detection_self_test_does_not_convict_benign_bytes() {
        let engine = DetectionEngine::builtin().unwrap();
        assert_eq!(
            engine
                .scan_bytes(b"an ordinary sentence with no payload in it")
                .verdict,
            DetectionVerdict::Clean
        );
    }

    #[test]
    fn the_userland_tier_uses_the_detection_self_test() {
        let engine = DetectionEngine::builtin().unwrap();
        assert!(run_tiered_self_test(ProtectionTier::Userland, &engine).is_ok());
    }
}
