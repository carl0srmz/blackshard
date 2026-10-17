#![no_main]

use libfuzzer_sys::fuzz_target;

// The header of every ClamAV container is parsed before its signature is checked, so it is the
// first thing a hostile mirror controls.
fuzz_target!(|data: &[u8]| {
    let _ = blackshard::clamdb::cvd::CvdHeader::parse(data);
});
