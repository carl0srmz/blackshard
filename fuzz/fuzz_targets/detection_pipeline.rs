#![no_main]

use blackshard::detection::DetectionEngine;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// The whole pipeline: static engine, hash databases, YARA, similarity and the zip, OLE and gzip
// container walkers, nested. `scan_amsi_submission` is `scan_bytes` without the round trip
// through the system AMSI, which would hand every input to the machine's antivirus.
fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    static ENGINE: OnceLock<DetectionEngine> = OnceLock::new();
    let engine = ENGINE.get_or_init(|| DetectionEngine::builtin().expect("built-in engine"));
    let _ = engine.scan_amsi_submission(data);
});
