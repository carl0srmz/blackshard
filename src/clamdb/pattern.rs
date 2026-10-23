//! ClamAV body signatures (`.ndb`): byte patterns that match inside a file.
//!
//! A line is `Name:TargetType:Offset:HexSignature`. The hex signature is a run of bytes with
//! wildcards between them. Hash signatures identify one exact file; these identify a family,
//! because the bytes that make a malware family what it is survive repacking and small edits.
//!
//! What is understood: target types any, PE, OLE2, ELF and PDF; offsets `*`, absolute, and
//! `EOF-n`; bytes, `??` for any byte, `*` for any run of bytes, and `{n}`, `{n-m}`, `{-m}` and
//! `{n-}` for a run of bounded length. Anything else (alternatives, nibble wildcards, `EP+n` and
//! section-relative offsets, normalized text targets) is counted and skipped, never guessed at.
//!
//! Matching is two stage. Every signature contributes its longest run of fixed bytes to one
//! Aho-Corasick automaton, which finds candidates in a single pass; only a candidate is checked
//! against the whole signature. A signature with no fixed run of at least [`MIN_ANCHOR`] bytes, or
//! fewer than [`MIN_FIXED_BYTES`] fixed bytes in all, is too weak to convict on and is skipped.

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

/// The shortest fixed run a signature may be found by.
const MIN_ANCHOR: usize = 4;
/// Fewer fixed bytes in all than this is too likely to occur in a clean file.
const MIN_FIXED_BYTES: usize = 8;
/// How far a `*` is followed before giving up, and the most byte comparisons one candidate may
/// cost. A signature that cannot be confirmed within them is a miss, never a hang.
const MAX_UNBOUNDED_GAP: usize = 1 << 20;
const MAX_VERIFY_STEPS: usize = 4 << 20;
const MAX_SIGNATURE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Any,
    Pe,
    Ole2,
    Elf,
    Pdf,
}

impl Target {
    fn applies_to(self, text: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Pe => text.starts_with(b"MZ"),
            Self::Ole2 => text.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
            Self::Elf => text.starts_with(b"\x7fELF"),
            Self::Pdf => text[..text.len().min(1024)]
                .windows(4)
                .any(|window| window == b"%PDF"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offset {
    Anywhere,
    /// The signature starts exactly here.
    Absolute(usize),
    /// The signature starts this many bytes before the end of the file.
    FromEnd(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// Bytes to match; `None` is a wildcard byte.
    Bytes(Vec<Option<u8>>),
    /// A run of `min` to `max` (or unbounded) arbitrary bytes.
    Gap { min: usize, max: Option<usize> },
}

#[derive(Debug, Clone)]
struct Signature {
    name: String,
    target: Target,
    offset: Offset,
    parts: Vec<Part>,
    /// Which part holds the anchor, and where in that part it begins.
    anchor_part: usize,
    anchor_start: usize,
}

/// How many signature lines a load kept and why it dropped the rest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatternStats {
    pub loaded: usize,
    pub unsupported: usize,
    pub too_weak: usize,
}

#[derive(Default)]
pub struct PatternSet {
    signatures: Vec<Signature>,
    /// Anchors waiting for [`PatternSet::build`].
    pending: Vec<Vec<u8>>,
    automaton: Option<AhoCorasick>,
}

impl std::fmt::Debug for PatternSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PatternSet")
            .field("signatures", &self.signatures.len())
            .finish()
    }
}

impl Clone for PatternSet {
    fn clone(&self) -> Self {
        // The automaton is large and cheap to rebuild from the anchors it was made of; a clone
        // is only ever taken of a set that is about to be rebuilt anyway.
        let mut clone = Self {
            signatures: self.signatures.clone(),
            pending: self.signatures.iter().map(Signature::anchor).collect(),
            automaton: None,
        };
        clone.build();
        clone
    }
}

impl Signature {
    fn anchor(&self) -> Vec<u8> {
        let Part::Bytes(bytes) = &self.parts[self.anchor_part] else {
            unreachable!("the anchor is always inside a byte part");
        };
        bytes[self.anchor_start..]
            .iter()
            .map_while(|byte| *byte)
            .collect()
    }
}

impl PatternSet {
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Reads one `.ndb` line. Returns whether it was kept, and counts why not in `stats`.
    pub fn ingest(&mut self, line: &str, stats: &mut PatternStats) -> bool {
        match parse_line(line) {
            Parsed::Kept(signature) => {
                self.pending.push(signature.anchor());
                self.signatures.push(signature);
                stats.loaded += 1;
                true
            }
            Parsed::Unsupported => {
                stats.unsupported += 1;
                false
            }
            Parsed::TooWeak => {
                stats.too_weak += 1;
                false
            }
        }
    }

    /// Builds the automaton once everything is loaded. Idempotent.
    pub fn build(&mut self) {
        if self.pending.len() != self.signatures.len() || self.signatures.is_empty() {
            self.automaton = None;
            return;
        }
        self.automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&self.pending)
            .ok();
    }

    /// The name of the first signature `text` matches.
    ///
    /// `truncated` says `text` is only the start of a larger file of `file_size` bytes, so
    /// signatures anchored to the end of the file cannot be judged.
    pub fn scan(&self, text: &[u8], file_size: u64, truncated: bool) -> Option<&str> {
        let automaton = self.automaton.as_ref()?;
        let mut steps = 0usize;
        for found in automaton.find_overlapping_iter(text) {
            let signature = &self.signatures[found.pattern().as_usize()];
            if !signature.target.applies_to(text) {
                continue;
            }
            if verify(
                signature,
                text,
                found.start(),
                file_size,
                truncated,
                &mut steps,
            ) {
                return Some(&signature.name);
            }
            if steps > MAX_VERIFY_STEPS * 16 {
                // One adversarial file must not be allowed to cost minutes.
                return None;
            }
        }
        None
    }
}

enum Parsed {
    Kept(Signature),
    Unsupported,
    TooWeak,
}

fn parse_line(line: &str) -> Parsed {
    let fields: Vec<&str> = line.trim().split(':').collect();
    if fields.len() < 4 {
        return Parsed::Unsupported;
    }
    let name = fields[0].trim();
    if name.is_empty() {
        return Parsed::Unsupported;
    }
    let target = match fields[1].trim() {
        "0" => Target::Any,
        "1" => Target::Pe,
        "2" => Target::Ole2,
        "6" => Target::Elf,
        "10" => Target::Pdf,
        _ => return Parsed::Unsupported,
    };
    let offset = match fields[2].trim() {
        "*" => Offset::Anywhere,
        text if text.starts_with("EOF-") => match text[4..].parse() {
            Ok(distance) => Offset::FromEnd(distance),
            Err(_) => return Parsed::Unsupported,
        },
        text => match text.parse() {
            Ok(position) => Offset::Absolute(position),
            Err(_) => return Parsed::Unsupported,
        },
    };
    let Some(parts) = parse_hex(fields[3].trim()) else {
        return Parsed::Unsupported;
    };

    let fixed: usize = parts
        .iter()
        .map(|part| match part {
            Part::Bytes(bytes) => bytes.iter().flatten().count(),
            Part::Gap { .. } => 0,
        })
        .sum();
    if fixed < MIN_FIXED_BYTES {
        return Parsed::TooWeak;
    }
    // The longest run of fixed bytes anywhere in the signature.
    let mut best: Option<(usize, usize, usize)> = None;
    for (index, part) in parts.iter().enumerate() {
        let Part::Bytes(bytes) = part else { continue };
        let mut start = 0;
        while start < bytes.len() {
            if bytes[start].is_none() {
                start += 1;
                continue;
            }
            let length = bytes[start..]
                .iter()
                .take_while(|byte| byte.is_some())
                .count();
            if best.is_none_or(|(_, _, longest)| length > longest) {
                best = Some((index, start, length));
            }
            start += length;
        }
    }
    let Some((anchor_part, anchor_start, length)) = best else {
        return Parsed::TooWeak;
    };
    if length < MIN_ANCHOR {
        return Parsed::TooWeak;
    }
    Parsed::Kept(Signature {
        name: name.to_owned(),
        target,
        offset,
        parts,
        anchor_part,
        anchor_start,
    })
}

/// Hex digits, `??`, `*` and `{…}` into parts. `None` for anything this matcher does not model.
fn parse_hex(text: &str) -> Option<Vec<Part>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES * 2 + 64 {
        return None;
    }
    let mut parts: Vec<Part> = Vec::new();
    let mut run: Vec<Option<u8>> = Vec::new();
    let mut index = 0;
    let flush = |run: &mut Vec<Option<u8>>, parts: &mut Vec<Part>| {
        if !run.is_empty() {
            parts.push(Part::Bytes(std::mem::take(run)));
        }
    };
    while index < bytes.len() {
        match bytes[index] {
            b'*' => {
                flush(&mut run, &mut parts);
                parts.push(Part::Gap { min: 0, max: None });
                index += 1;
            }
            b'{' => {
                let close = text[index..].find('}')? + index;
                let (min, max) = parse_range(&text[index + 1..close])?;
                flush(&mut run, &mut parts);
                parts.push(Part::Gap { min, max });
                index = close + 1;
            }
            b'?' if bytes.get(index + 1) == Some(&b'?') => {
                run.push(None);
                index += 2;
            }
            high => {
                let low = *bytes.get(index + 1)?;
                let value = u8::from_str_radix(std::str::from_utf8(&[high, low]).ok()?, 16).ok()?;
                run.push(Some(value));
                index += 2;
            }
        }
    }
    flush(&mut run, &mut parts);

    // Merge adjacent gaps; a gap at either end is meaningful only as `*`, which says nothing.
    let mut merged: Vec<Part> = Vec::new();
    for part in parts {
        match (merged.last_mut(), part) {
            (
                Some(Part::Gap { min, max }),
                Part::Gap {
                    min: more,
                    max: more_max,
                },
            ) => {
                *min += more;
                *max = max.zip(more_max).map(|(left, right)| left + right);
            }
            (_, part) => merged.push(part),
        }
    }
    if matches!(merged.first(), Some(Part::Gap { min: 0, max: None })) {
        merged.remove(0);
    }
    if matches!(merged.last(), Some(Part::Gap { min: 0, max: None })) {
        merged.pop();
    }
    if matches!(merged.first(), Some(Part::Gap { .. }))
        || matches!(merged.last(), Some(Part::Gap { .. }))
        || merged.is_empty()
    {
        return None;
    }
    Some(merged)
}

fn parse_range(text: &str) -> Option<(usize, Option<usize>)> {
    let (min, max) = match text.split_once('-') {
        None => {
            let exact = text.parse().ok()?;
            (exact, Some(exact))
        }
        Some(("", max)) => (0, Some(max.parse().ok()?)),
        Some((min, "")) => (min.parse().ok()?, None),
        Some((min, max)) => (min.parse().ok()?, Some(max.parse().ok()?)),
    };
    if max.is_some_and(|max| max < min) || min > MAX_UNBOUNDED_GAP {
        return None;
    }
    Some((min, max))
}

fn bytes_match(pattern: &[Option<u8>], text: &[u8]) -> bool {
    pattern.len() == text.len()
        && pattern
            .iter()
            .zip(text)
            .all(|(wanted, actual)| wanted.is_none_or(|wanted| wanted == *actual))
}

/// Whether the whole signature matches with its anchor found at `anchor_at`.
fn verify(
    signature: &Signature,
    text: &[u8],
    anchor_at: usize,
    file_size: u64,
    truncated: bool,
    steps: &mut usize,
) -> bool {
    let Part::Bytes(anchor_bytes) = &signature.parts[signature.anchor_part] else {
        return false;
    };
    let Some(part_start) = anchor_at.checked_sub(signature.anchor_start) else {
        return false;
    };
    let part_end = part_start + anchor_bytes.len();
    if part_end > text.len() || !bytes_match(anchor_bytes, &text[part_start..part_end]) {
        return false;
    }
    let before = &signature.parts[..signature.anchor_part];
    let after = &signature.parts[signature.anchor_part + 1..];
    let Some(start) = match_left(before, text, part_start, steps) else {
        return false;
    };
    let Some(end) = match_right(after, text, part_end, steps) else {
        return false;
    };
    match signature.offset {
        Offset::Anywhere => true,
        Offset::Absolute(position) => start == position,
        Offset::FromEnd(distance) => {
            !truncated
                && file_size as usize == text.len()
                && text.len().checked_sub(distance) == Some(start)
                && end <= text.len()
        }
    }
}

/// Matches `parts` forward from `position`; returns where the match ends.
fn match_right(parts: &[Part], text: &[u8], position: usize, steps: &mut usize) -> Option<usize> {
    let Some((first, rest)) = parts.split_first() else {
        return Some(position);
    };
    match first {
        Part::Bytes(bytes) => {
            *steps += bytes.len();
            let end = position.checked_add(bytes.len())?;
            if *steps > MAX_VERIFY_STEPS
                || end > text.len()
                || !bytes_match(bytes, &text[position..end])
            {
                return None;
            }
            match_right(rest, text, end, steps)
        }
        Part::Gap { min, max } => {
            let limit = max.unwrap_or(MAX_UNBOUNDED_GAP).min(MAX_UNBOUNDED_GAP);
            for skip in *min..=limit {
                *steps += 1;
                if *steps > MAX_VERIFY_STEPS || position + skip > text.len() {
                    return None;
                }
                if let Some(end) = match_right(rest, text, position + skip, steps) {
                    return Some(end);
                }
            }
            None
        }
    }
}

/// Matches `parts` backward from `end`; returns where the match starts.
fn match_left(parts: &[Part], text: &[u8], end: usize, steps: &mut usize) -> Option<usize> {
    let Some((last, rest)) = parts.split_last() else {
        return Some(end);
    };
    match last {
        Part::Bytes(bytes) => {
            *steps += bytes.len();
            let start = end.checked_sub(bytes.len())?;
            if *steps > MAX_VERIFY_STEPS || !bytes_match(bytes, &text[start..end]) {
                return None;
            }
            match_left(rest, text, start, steps)
        }
        Part::Gap { min, max } => {
            let limit = max.unwrap_or(MAX_UNBOUNDED_GAP).min(MAX_UNBOUNDED_GAP);
            for skip in *min..=limit {
                *steps += 1;
                if *steps > MAX_VERIFY_STEPS {
                    return None;
                }
                let start = end.checked_sub(skip)?;
                if let Some(found) = match_left(rest, text, start, steps) {
                    return Some(found);
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(lines: &[&str]) -> (PatternSet, PatternStats) {
        let mut set = PatternSet::default();
        let mut stats = PatternStats::default();
        for line in lines {
            set.ingest(line, &mut stats);
        }
        set.build();
        (set, stats)
    }

    fn scan<'a>(set: &'a PatternSet, text: &[u8]) -> Option<&'a str> {
        set.scan(text, text.len() as u64, false)
    }

    const FAMILY: &str = "Win.Test.Family-1:0:*:deadbeef00112233";

    #[test]
    fn a_fixed_pattern_matches_anywhere() {
        let (set, stats) = set(&[FAMILY]);
        assert_eq!(stats.loaded, 1);
        let mut text = vec![0x41; 100];
        text.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
        text.extend_from_slice(&[0x42; 50]);
        assert_eq!(scan(&set, &text), Some("Win.Test.Family-1"));
        assert_eq!(scan(&set, &[0x41; 300]), None);
        // One byte off is a miss.
        let mut near = text.clone();
        near[107] = 0x34;
        assert_eq!(scan(&set, &near), None);
    }

    #[test]
    fn wildcards_and_gaps_are_honoured() {
        let (set, _) = set(&[
            "Win.Test.Wild:0:*:aabbccdd??eeff0011",
            "Win.Test.Gap:0:*:11223344{2-4}55667788",
            "Win.Test.Star:0:*:99887766*0a0b0c0d",
        ]);
        assert_eq!(
            scan(
                &set,
                &[0xaa, 0xbb, 0xcc, 0xdd, 0x77, 0xee, 0xff, 0x00, 0x11]
            ),
            Some("Win.Test.Wild")
        );
        let gap = |between: usize| {
            let mut text = vec![0x11, 0x22, 0x33, 0x44];
            text.extend(std::iter::repeat_n(0u8, between));
            text.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]);
            text
        };
        assert_eq!(scan(&set, &gap(3)), Some("Win.Test.Gap"));
        assert_eq!(scan(&set, &gap(1)), None);
        assert_eq!(scan(&set, &gap(5)), None);
        let mut star = vec![0x99, 0x88, 0x77, 0x66];
        star.extend(std::iter::repeat_n(7u8, 5000));
        star.extend_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(scan(&set, &star), Some("Win.Test.Star"));
    }

    #[test]
    fn the_anchor_need_not_be_the_first_part() {
        // The only run of four or more fixed bytes is in the middle.
        let (set, stats) = set(&["Win.Test.Middle:0:*:1122??{1-2}cafebabe??{0-3}3344"]);
        assert_eq!(stats.loaded, 1);
        let text = [
            0x11, 0x22, 0x99, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x77, 0x33, 0x44,
        ];
        assert_eq!(scan(&set, &text), Some("Win.Test.Middle"));
        let wrong = [
            0x11, 0x23, 0x99, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x77, 0x33, 0x44,
        ];
        assert_eq!(scan(&set, &wrong), None);
    }

    #[test]
    fn offsets_are_enforced() {
        let (set, _) = set(&[
            "Win.Test.Start:0:0:4d5a9000deadbeef",
            "Win.Test.At8:0:8:cafebabecafebabe",
            "Win.Test.End:0:EOF-8:0badc0de12345678",
        ]);
        let mut at_start = vec![0x4d, 0x5a, 0x90, 0x00, 0xde, 0xad, 0xbe, 0xef];
        at_start.extend_from_slice(&[0; 20]);
        assert_eq!(scan(&set, &at_start), Some("Win.Test.Start"));
        let mut later = vec![0; 4];
        later.extend_from_slice(&[0x4d, 0x5a, 0x90, 0x00, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(scan(&set, &later), None);

        let mut at_eight = vec![0u8; 8];
        at_eight.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(scan(&set, &at_eight), Some("Win.Test.At8"));

        let mut at_end = vec![0u8; 30];
        at_end.extend_from_slice(&[0x0b, 0xad, 0xc0, 0xde, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(scan(&set, &at_end), Some("Win.Test.End"));
        // Anchored to the end of a file whose end was not read: no verdict.
        assert_eq!(set.scan(&at_end, 10_000, true), None);
    }

    #[test]
    fn targets_restrict_where_a_signature_applies() {
        let (set, _) = set(&["Win.Test.Pe:1:*:deadbeefcafef00d"]);
        let body = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xf0, 0x0d];
        let mut pe = b"MZ".to_vec();
        pe.extend_from_slice(&body);
        assert_eq!(scan(&set, &pe), Some("Win.Test.Pe"));
        assert_eq!(scan(&set, &body), None, "not a PE");
    }

    #[test]
    fn weak_and_unsupported_signatures_are_dropped_not_guessed() {
        let (set, stats) = set(&[
            "Weak.Short:0:*:aabbccdd",
            "Weak.NoAnchor:0:*:aa??bb??cc??dd??ee",
            "Unsupported.Alternation:0:*:(aabb|ccdd)11223344556677",
            "Unsupported.Nibble:0:*:aab?ccdd11223344",
            "Unsupported.EntryPoint:1:EP+10:11223344556677889900",
            "Unsupported.Text:7:*:11223344556677889900",
            "garbage",
            "",
        ]);
        assert_eq!(stats.loaded, 0);
        assert_eq!(stats.too_weak, 2);
        assert_eq!(stats.unsupported, 6);
        assert!(set.is_empty());
        assert_eq!(scan(&set, b"anything"), None);
    }

    #[test]
    fn a_hostile_pattern_cannot_run_forever() {
        let (set, _) = set(&["Win.Test.Slow:0:*:aaaaaaaa*bbbbbbbb*cccccccc*dddddddd"]);
        let mut text = vec![0xaa; 600_000];
        text.extend(std::iter::repeat_n(0xbb, 600_000));
        text.extend(std::iter::repeat_n(0xcc, 600_000));
        let started = std::time::Instant::now();
        let _ = scan(&set, &text);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn cloning_keeps_the_signatures_working() {
        let (set, _) = set(&[FAMILY]);
        let clone = set.clone();
        let text = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
        assert_eq!(scan(&clone, &text), Some("Win.Test.Family-1"));
    }
}
