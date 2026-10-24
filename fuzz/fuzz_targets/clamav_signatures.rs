#![no_main]

use blackshard::clamdb::pattern::{PatternSet, PatternStats};
use libfuzzer_sys::fuzz_target;

// Signature lines (`.ndb` and `.ldb`), then a zero byte, then the text they are matched against.
// The databases come from a signed feed, but a parser of hundreds of thousands of lines written
// by other people should still survive anything, and so should the matcher run over any file.
fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    let (lines, text) = data.split_at(split);
    let Ok(lines) = std::str::from_utf8(lines) else {
        return;
    };
    let mut set = PatternSet::default();
    let mut stats = PatternStats::default();
    for line in lines.lines().take(64) {
        if line.contains(';') {
            set.ingest_logical(line, &mut stats);
        } else {
            set.ingest(line, &mut stats);
        }
    }
    set.build();
    let text = text.get(1..).unwrap_or(&[]);
    let _ = set.scan(text, text.len() as u64, false);
    let _ = set.scan(text, text.len() as u64 + 10, true);
});
