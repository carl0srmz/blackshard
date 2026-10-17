#![no_main]

use blackshard::detection::DetectionEngine;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use std::thread;

// The whole pipeline: static engine, hash databases, YARA, similarity and the zip, OLE and gzip
// container walkers, nested. `scan_amsi_submission` is `scan_bytes` without the round trip
// through the system AMSI, which would hand every input to the machine's antivirus.
//
// Compiling the YARA rules goes through wasmtime's code generator, which under AddressSanitizer
// needs far more than the 1 MB stack Windows gives a process's main thread. The engine is built,
// and each input scanned, on a thread with room to spare; the service's own threads are not
// instrumented and do not need it.
const STACK_BYTES: usize = 256 * 1024 * 1024;

fn on_large_stack<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    thread::scope(|scope| {
        thread::Builder::new()
            .stack_size(STACK_BYTES)
            .spawn_scoped(scope, work)
            .expect("could not start the fuzzing thread")
            .join()
            // A panic in the pipeline is a finding: hand it to libFuzzer as one.
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    static ENGINE: OnceLock<DetectionEngine> = OnceLock::new();
    on_large_stack(|| {
        let engine = ENGINE.get_or_init(|| DetectionEngine::builtin().expect("built-in engine"));
        let _ = engine.scan_amsi_submission(data);
    });
});
