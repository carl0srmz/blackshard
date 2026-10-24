//! ClamAV body signatures (`.ndb`): byte patterns that match inside a file.
//!
//! A line is `Name:TargetType:Offset:HexSignature`. The hex signature is a run of bytes with
//! wildcards between them. Hash signatures identify one exact file; these identify a family,
//! because the bytes that make a malware family what it is survive repacking and small edits.
//!
//! What is understood: target types any, PE, OLE2, ELF and PDF; offsets `*`, absolute, and
//! `EOF-n`, `EP+n`/`EP-n` and `Sx+n`/`SL+n` (relative to the entry point or a PE section), each
//! optionally followed by `,shift`; bytes, `??` for any byte, `*` for any run of bytes, and `{n}`, `{n-m}`, `{-m}` and
//! `{n-}` for a run of bounded length. In `.ldb` pieces that are plain byte runs, the modifiers
//! `i`, `w`, `a` and `f` are understood too. Anything else (alternatives, nibble wildcards,
//! normalized text targets) is counted and skipped, never guessed at.
//!
//! Matching is two stage. Every signature contributes its longest run of fixed bytes to one
//! Aho-Corasick automaton, which finds candidates in a single pass; only a candidate is checked
//! against the whole signature. A signature with no fixed run of at least [`MIN_ANCHOR`] bytes, or
//! fewer than [`MIN_FIXED_BYTES`] fixed bytes in all, is too weak to convict on and is skipped.

use super::logical::Expr;
use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder, MatchKind};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// The shortest fixed run a signature may be found by.
const MIN_ANCHOR: usize = 4;
/// Fewer fixed bytes in all than this is too likely to occur in a clean file.
const MIN_FIXED_BYTES: usize = 8;
/// How far a `*` is followed before giving up, and the most byte comparisons one candidate may
/// cost. A signature that cannot be confirmed within them is a miss, never a hang.
const MAX_UNBOUNDED_GAP: usize = 1 << 20;
const MAX_VERIFY_STEPS: usize = 4 << 20;
const MAX_SIGNATURE_BYTES: usize = 4096;
/// A logical signature joins weak pieces, so what its expression needs in all must be about as
/// strong as one stand-alone body signature twice over.
const MIN_LOGICAL_FIXED_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Target {
    Any,
    Pe,
    Ole2,
    Elf,
    Pdf,
}

impl Target {
    const ALL: [Target; 5] = [Self::Any, Self::Pe, Self::Ole2, Self::Elf, Self::Pdf];

    fn index(self) -> usize {
        match self {
            Self::Any => 0,
            Self::Pe => 1,
            Self::Ole2 => 2,
            Self::Elf => 3,
            Self::Pdf => 4,
        }
    }

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

/// Where a signature may start: at `base`, or up to `shift` bytes after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Offset {
    base: Base,
    shift: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Base {
    Anywhere,
    Absolute(usize),
    /// This many bytes before the end of the file.
    FromEnd(usize),
    /// Relative to the entry point's position in the file.
    EntryPoint(isize),
    /// This many bytes into section `index` (the last one when `None`).
    Section {
        index: Option<usize>,
        delta: usize,
    },
}

/// Where the parts of a PE sit in the file, found only when a signature needs them.
#[derive(Debug, Clone, Default)]
struct PeLayout {
    entry_point: Option<usize>,
    sections: Vec<usize>,
}

impl PeLayout {
    fn read(text: &[u8]) -> Self {
        let u16_at = |at: usize| -> Option<usize> {
            Some(u16::from_le_bytes(text.get(at..at + 2)?.try_into().ok()?) as usize)
        };
        let u32_at = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(text.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let parse = || -> Option<Self> {
            let header = u32_at(0x3c)?;
            if text.get(header..header + 4)? != b"PE\0\0" {
                return None;
            }
            let section_count = u16_at(header + 6)?.min(96);
            let optional_size = u16_at(header + 20)?;
            let optional = header + 24;
            let entry_rva = u32_at(optional + 16)?;
            let table = optional + optional_size;
            let mut sections = Vec::new();
            let mut entry_point = None;
            for index in 0..section_count {
                let at = table + index * 40;
                let virtual_size = u32_at(at + 8)?;
                let virtual_address = u32_at(at + 12)?;
                let raw_size = u32_at(at + 16)?;
                let raw_pointer = u32_at(at + 20)?;
                sections.push(raw_pointer);
                let span = virtual_size.max(raw_size);
                if entry_point.is_none()
                    && entry_rva >= virtual_address
                    && entry_rva < virtual_address.saturating_add(span)
                {
                    entry_point = Some(raw_pointer + (entry_rva - virtual_address));
                }
            }
            Some(Self {
                entry_point,
                sections,
            })
        };
        parse().unwrap_or_default()
    }

    /// The first position `base` allows, if this file has what it is relative to.
    fn resolve(&self, base: Base, file_len: usize) -> Option<usize> {
        match base {
            Base::Anywhere => Some(0),
            Base::Absolute(position) => Some(position),
            Base::FromEnd(distance) => file_len.checked_sub(distance),
            Base::EntryPoint(delta) => self.entry_point?.checked_add_signed(delta),
            Base::Section { index, delta } => {
                let start = match index {
                    Some(index) => *self.sections.get(index)?,
                    None => *self.sections.last()?,
                };
                start.checked_add(delta)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    anchor_len: usize,
    /// A piece of logical signatures rather than a signature of its own: its matches are only
    /// counted, and the logical signatures that use it are judged once the scan is over.
    piece: bool,
    /// ASCII letters match in either case (`::i`).
    fold: bool,
    /// The match must not touch a letter or digit on either side (`::f`).
    fullword: bool,
}

/// A `.ldb` signature: sub-signatures and the expression over how often each matched.
#[derive(Debug, Clone)]
struct Logical {
    name: String,
    /// Inclusive bounds on the size of the whole file.
    file_size: Option<(u64, u64)>,
    expression: Expr,
    /// Number of sub-signatures, which the expression numbers.
    slots: usize,
    /// The pieces that stand for the sub-signatures, and for each the sub-signature it is. A
    /// sub-signature written for both ascii and wide text has two pieces.
    pieces: Vec<u32>,
    slot_of: Vec<u8>,
}

/// What identifies a piece, so a piece shared by many logical signatures is kept, found and
/// counted once.
type PieceKey = (Target, Offset, Vec<Part>, bool, bool);

/// Which logical signatures use each piece, as one flat array: the users of piece `p` are
/// `users[starts[p]..starts[p + 1]]`.
#[derive(Default)]
struct PieceUsers {
    starts: Vec<u32>,
    users: Vec<u32>,
}

impl PieceUsers {
    fn of(&self, piece: usize) -> &[u32] {
        match (self.starts.get(piece), self.starts.get(piece + 1)) {
            (Some(start), Some(end)) => &self.users[*start as usize..*end as usize],
            _ => &[],
        }
    }
}

/// How many signature lines a load kept and why it dropped the rest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatternStats {
    pub loaded: usize,
    pub unsupported: usize,
    pub too_weak: usize,
    /// How many lines each kind of unmodelled feature cost, to show what to build next.
    pub reasons: std::collections::BTreeMap<&'static str, usize>,
}

#[derive(Default)]
pub struct PatternSet {
    signatures: Vec<Signature>,
    logicals: Vec<Logical>,
    /// Finds every signature's anchor, in lowercase, in a lowercased copy of the text: one pass
    /// serves case-sensitive and case-insensitive signatures alike. A case-sensitive signature's
    /// whole match is then checked against the original text, which settles its case.
    anchors: Option<Anchors>,
    /// The pieces already stored, so identical ones are shared.
    piece_index: HashMap<PieceKey, u32>,
    users: PieceUsers,
    /// Anchor occurrences found, and how many were then checked against their whole signature,
    /// over every scan since the set was built. They show where scan time goes.
    anchor_hits: AtomicU64,
    verifications: AtomicU64,
}

/// An automaton over anchors, and which signatures each anchor belongs to.
struct Anchors {
    automaton: DoubleArrayAhoCorasick<u32>,
    signatures: Vec<Vec<usize>>,
}

impl Anchors {
    /// `None` when there are no anchors, or the automaton cannot be built.
    fn build(anchors: Vec<(Vec<u8>, usize)>) -> Option<Self> {
        let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut signatures: Vec<Vec<usize>> = Vec::new();
        for (anchor, signature) in anchors {
            // The automaton refuses duplicates; several signatures may share one anchor.
            let group = *seen.entry(anchor.clone()).or_insert_with(|| {
                patterns.push(anchor);
                signatures.push(Vec::new());
                patterns.len() - 1
            });
            signatures[group].push(signature);
        }
        if patterns.is_empty() {
            return None;
        }
        let automaton = DoubleArrayAhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .ok()?;
        Some(Self {
            automaton,
            signatures,
        })
    }

    /// Calls `found(group, start)` for every occurrence of every anchor in `text`, until it
    /// returns `false`.
    fn for_each_match<F: FnMut(usize, usize) -> bool>(&self, text: &[u8], mut found: F) {
        for hit in self.automaton.find_overlapping_iter(text) {
            if !found(hit.value() as usize, hit.start()) {
                return;
            }
        }
    }
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
            logicals: self.logicals.clone(),
            anchors: None,
            piece_index: self.piece_index.clone(),
            users: PieceUsers::default(),
            anchor_hits: AtomicU64::new(0),
            verifications: AtomicU64::new(0),
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
        bytes[self.anchor_start..self.anchor_start + self.anchor_len]
            .iter()
            .map_while(|byte| *byte)
            .collect()
    }
}

impl PatternSet {
    /// Body signatures and logical signatures kept.
    pub fn len(&self) -> usize {
        self.signatures
            .iter()
            .filter(|signature| !signature.piece)
            .count()
            + self.logicals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Reads one `.ndb` line. Returns whether it was kept, and counts why not in `stats`.
    pub fn ingest(&mut self, line: &str, stats: &mut PatternStats) -> bool {
        match parse_line(line) {
            Parsed::Kept(signature) => {
                self.signatures.push(signature);
                stats.loaded += 1;
                true
            }
            Parsed::Unsupported(reason) => {
                stats.unsupported += 1;
                *stats.reasons.entry(reason).or_default() += 1;
                false
            }
            Parsed::TooWeak => {
                stats.too_weak += 1;
                false
            }
        }
    }

    /// Reads one `.ldb` line: `Name;TargetBlock;Expression;Sub0;Sub1;...`. Returns whether it
    /// was kept. A signature with any piece this matcher cannot model is dropped whole, because
    /// the expression cannot be judged without all of them.
    pub fn ingest_logical(&mut self, line: &str, stats: &mut PatternStats) -> bool {
        match self.parse_logical(line) {
            Ok(()) => {
                stats.loaded += 1;
                true
            }
            Err(Parsed::TooWeak) => {
                stats.too_weak += 1;
                false
            }
            Err(Parsed::Unsupported(reason)) => {
                stats.unsupported += 1;
                *stats.reasons.entry(reason).or_default() += 1;
                false
            }
            Err(Parsed::Kept(_)) => false,
        }
    }

    /// `Err` carries why the line was not kept.
    fn parse_logical(&mut self, line: &str) -> Result<(), Parsed> {
        let fields: Vec<&str> = line.trim().split(';').collect();
        if fields.len() < 4 || fields.len() - 3 > MAX_LOGICAL_SUBSIGNATURES {
            return Err(Parsed::Unsupported("ldb: malformed or too many pieces"));
        }
        let name = fields[0].trim();
        if name.is_empty() {
            return Err(Parsed::Unsupported("ldb: malformed or too many pieces"));
        }
        let Some((target, file_size)) = parse_target_block(fields[1].trim()) else {
            return Err(Parsed::Unsupported("ldb: target block condition"));
        };
        let Some(expression) = Expr::parse(fields[2].trim()) else {
            return Err(Parsed::Unsupported("ldb: expression form"));
        };
        let subsignatures = fields.len() - 3;
        // Every sub-signature must be used, or the line was split wrongly (a `;` inside one).
        let mut used = Vec::new();
        expression.subsignatures(&mut used);
        used.sort_unstable();
        used.dedup();
        if used != (0..subsignatures).collect::<Vec<_>>() {
            return Err(Parsed::Unsupported("ldb: pieces and expression disagree"));
        }

        // A piece can stand for several signatures (ascii and wide); they share one slot.
        let mut built: Vec<Vec<Signature>> = Vec::with_capacity(subsignatures);
        let mut fixed = Vec::with_capacity(subsignatures);
        for field in &fields[3..] {
            let variants = parse_piece(name, target, field.trim())?;
            fixed.push(variants.first().map_or(0, fixed_bytes_narrow));
            built.push(variants);
        }
        let needed = expression.required_bytes(&fixed);
        let floor = if matches!(expression, Expr::Seen(_)) {
            MIN_FIXED_BYTES
        } else {
            MIN_LOGICAL_FIXED_BYTES
        };
        if needed < floor {
            return Err(Parsed::TooWeak);
        }

        let mut pieces = Vec::new();
        let mut slot_of = Vec::new();
        for (slot, variants) in built.into_iter().enumerate() {
            for mut signature in variants {
                signature.piece = true;
                signature.name = String::new();
                let key = (
                    signature.target,
                    signature.offset,
                    signature.parts.clone(),
                    signature.fold,
                    signature.fullword,
                );
                let next = self.signatures.len() as u32;
                let id = *self.piece_index.entry(key).or_insert(next);
                if id == next {
                    self.signatures.push(signature);
                }
                pieces.push(id);
                slot_of.push(slot as u8);
            }
        }
        self.logicals.push(Logical {
            name: name.to_owned(),
            file_size,
            expression,
            slots: subsignatures,
            pieces,
            slot_of,
        });
        Ok(())
    }

    /// Builds the automaton once everything is loaded. Idempotent.
    pub fn build(&mut self) {
        let anchors = self
            .signatures
            .iter()
            .enumerate()
            .map(|(index, signature)| (signature.anchor().to_ascii_lowercase(), index))
            .collect();
        self.anchors = Anchors::build(anchors);

        // Which logical signatures use each piece.
        let mut starts = vec![0u32; self.signatures.len() + 1];
        for logical in &self.logicals {
            for piece in &logical.pieces {
                starts[*piece as usize + 1] += 1;
            }
        }
        for index in 1..starts.len() {
            starts[index] += starts[index - 1];
        }
        let mut next = starts.clone();
        let mut users = vec![0u32; starts[starts.len() - 1] as usize];
        for (index, logical) in self.logicals.iter().enumerate() {
            for piece in &logical.pieces {
                let at = &mut next[*piece as usize];
                users[*at as usize] = index as u32;
                *at += 1;
            }
        }
        self.users = PieceUsers { starts, users };
    }

    /// The name of the first signature `text` matches.
    ///
    /// `truncated` says `text` is only the start of a larger file of `file_size` bytes, so
    /// signatures anchored to the end of the file cannot be judged, and neither can a logical
    /// signature, whose expression may depend on something not being there.
    pub fn scan(&self, text: &[u8], file_size: u64, truncated: bool) -> Option<&str> {
        let (mut hits, mut verified) = (0u64, 0u64);
        let found = self.scan_counting(text, file_size, truncated, &mut hits, &mut verified);
        self.anchor_hits.fetch_add(hits, Ordering::Relaxed);
        self.verifications.fetch_add(verified, Ordering::Relaxed);
        found
    }

    /// `(anchor occurrences, whole-signature checks)` over all scans so far.
    pub fn work(&self) -> (u64, u64) {
        (
            self.anchor_hits.load(Ordering::Relaxed),
            self.verifications.load(Ordering::Relaxed),
        )
    }

    fn scan_counting(
        &self,
        text: &[u8],
        file_size: u64,
        truncated: bool,
        hits: &mut u64,
        verified: &mut u64,
    ) -> Option<&str> {
        let anchors = self.anchors.as_ref()?;
        let mut steps = 0usize;
        let mut layout: Option<PeLayout> = None;
        // Which kinds of file this is, decided once rather than at every hit.
        let applies = Target::ALL.map(|target| target.applies_to(text));
        let lowered = text.to_ascii_lowercase();
        SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.prepare(self.signatures.len(), self.logicals.len());
            let scratch = &mut *scratch;
            // Set when a body signature matches, or the scan gives up.
            let mut verdict: Option<Option<&str>> = None;
            anchors.for_each_match(&lowered, |group, start| {
                for &index in &anchors.signatures[group] {
                    *hits += 1;
                    let signature = &self.signatures[index];
                    if !applies[signature.target.index()] || (signature.piece && truncated) {
                        continue;
                    }
                    // Read once per file, and only when a signature is a candidate.
                    let layout = &*layout.get_or_insert_with(|| PeLayout::read(text));
                    let context = Context {
                        text,
                        file_size,
                        truncated,
                        layout,
                    };
                    *verified += 1;
                    if verify(signature, &context, start, &mut steps) {
                        if !signature.piece {
                            verdict = Some(Some(signature.name.as_str()));
                            return false;
                        }
                        let counter = &mut scratch.counts[index];
                        if *counter == 0 {
                            scratch.touched.push(index as u32);
                        }
                        *counter = counter.saturating_add(1);
                    }
                    if steps > MAX_VERIFY_STEPS * 16 {
                        // One adversarial file must not be allowed to cost minutes.
                        verdict = Some(None);
                        return false;
                    }
                }
                true
            });
            if let Some(verdict) = verdict {
                scratch.clear();
                return verdict;
            }

            // Judge, once, each logical signature that has a piece in this file.
            for piece in 0..scratch.touched.len() {
                for &user in self.users.of(scratch.touched[piece] as usize) {
                    if !scratch.marked[user as usize] {
                        scratch.marked[user as usize] = true;
                        scratch.candidates.push(user);
                    }
                }
            }
            // The lowest index that holds, so the answer does not depend on hit order.
            let mut found: Option<u32> = None;
            for &candidate in &scratch.candidates {
                if found.is_some_and(|best| best < candidate) {
                    continue;
                }
                let logical = &self.logicals[candidate as usize];
                if !logical
                    .file_size
                    .is_none_or(|(least, most)| (least..=most).contains(&file_size))
                {
                    continue;
                }
                scratch.gathered.clear();
                scratch.gathered.resize(logical.slots, 0);
                for (piece, slot) in logical.pieces.iter().zip(&logical.slot_of) {
                    let seen = scratch.counts[*piece as usize];
                    let total = &mut scratch.gathered[*slot as usize];
                    *total = total.saturating_add(seen);
                }
                if logical.expression.holds(&scratch.gathered) {
                    found = Some(candidate);
                }
            }
            scratch.clear();
            found.map(|logical| self.logicals[logical as usize].name.as_str())
        })
    }
}

/// Per-thread counters for the pieces one scan finds, kept between scans so a scan allocates
/// nothing per hit. Everything a scan dirties is zeroed again before the next.
#[derive(Default)]
struct Scratch {
    /// How often each piece matched.
    counts: Vec<u32>,
    /// Pieces with a nonzero count.
    touched: Vec<u32>,
    /// Whether a logical signature is already in `candidates`.
    marked: Vec<bool>,
    /// Logical signatures with a piece in this file, to be judged.
    candidates: Vec<u32>,
    /// One logical signature's counts by sub-signature.
    gathered: Vec<u32>,
}

impl Scratch {
    fn clear(&mut self) {
        for piece in self.touched.drain(..) {
            if let Some(count) = self.counts.get_mut(piece as usize) {
                *count = 0;
            }
        }
        for candidate in self.candidates.drain(..) {
            if let Some(mark) = self.marked.get_mut(candidate as usize) {
                *mark = false;
            }
        }
    }

    fn prepare(&mut self, pieces: usize, logicals: usize) {
        self.clear();
        if self.counts.len() != pieces {
            self.counts.clear();
            self.counts.resize(pieces, 0);
        }
        if self.marked.len() != logicals {
            self.marked.clear();
            self.marked.resize(logicals, false);
        }
    }
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch::default());
}

enum Parsed {
    Kept(Signature),
    /// Uses something this matcher does not model; the reason names it.
    Unsupported(&'static str),
    TooWeak,
}

fn parse_line(line: &str) -> Parsed {
    let fields: Vec<&str> = line.trim().split(':').collect();
    if fields.len() < 4 {
        return Parsed::Unsupported("ndb: malformed line");
    }
    let name = fields[0].trim();
    if name.is_empty() {
        return Parsed::Unsupported("ndb: malformed line");
    }
    let target = match fields[1].trim() {
        "0" => Target::Any,
        "1" => Target::Pe,
        "2" => Target::Ole2,
        "6" => Target::Elf,
        "10" => Target::Pdf,
        _ => return Parsed::Unsupported("ndb: target type (text, mail, graphics, ...)"),
    };
    let Some(offset) = parse_offset(fields[2].trim()) else {
        return Parsed::Unsupported("ndb: offset form");
    };
    // Entry point and section offsets only mean something in a PE.
    if matches!(offset.base, Base::EntryPoint(_) | Base::Section { .. }) && target != Target::Pe {
        return Parsed::Unsupported("ndb: PE offset on a non-PE target");
    }
    build_signature(name, target, offset, fields[3].trim(), MIN_FIXED_BYTES)
}

/// A signature from its parts, kept only if it has at least `min_fixed` fixed bytes and a fixed
/// run to find it by.
fn build_signature(
    name: &str,
    target: Target,
    offset: Offset,
    hex: &str,
    min_fixed: usize,
) -> Parsed {
    let Some(parts) = parse_hex(hex) else {
        return Parsed::Unsupported(hex_reason(hex));
    };

    let fixed: usize = parts
        .iter()
        .map(|part| match part {
            Part::Bytes(bytes) => bytes.iter().flatten().count(),
            Part::Gap { .. } => 0,
        })
        .sum();
    if fixed < min_fixed {
        return Parsed::TooWeak;
    }
    let Some((anchor_part, anchor_start, anchor_len)) = best_anchor(&parts) else {
        return Parsed::TooWeak;
    };
    Parsed::Kept(Signature {
        name: name.to_owned(),
        target,
        offset,
        parts,
        anchor_part,
        anchor_start,
        anchor_len,
        piece: false,
        fold: false,
        fullword: false,
    })
}

/// The longest window of a signature's fixed bytes searched for as its anchor.
const MAX_ANCHOR: usize = 12;
/// A window with fewer different bytes than this (padding, a run of no-ops) is not worth
/// searching for, whatever its length.
const MIN_DISTINCT_BYTES: usize = 3;

/// How rare a byte is in executables: those that fill padding and make up common instructions
/// count for little.
fn byte_weight(byte: u8) -> f32 {
    match byte {
        0x00
        | 0xff
        | 0x90
        | 0xcc
        | 0x20
        | 0x0a
        | 0x0d
        | 0x01..=0x04
        | 0x08
        | 0x10
        | 0x24
        | 0x40..=0x5f
        | 0x83
        | 0x89
        | 0x8b
        | 0xe8
        | 0x0f
        | 0xc2
        | 0xc3 => 0.5,
        _ => 1.5,
    }
}

/// How unlikely `window` is to turn up by chance: its bytes' rarity, and how many differ.
fn window_score(window: &[u8]) -> f32 {
    let mut seen = [false; 256];
    let mut score = 0.0;
    for &byte in window {
        score += byte_weight(byte);
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            score += 0.5;
        }
    }
    score
}

/// Where to search for a signature: the rarest window of up to [`MAX_ANCHOR`] fixed bytes inside
/// any one run of them, as `(part, start in part, length)`. `None` if there is no window of at
/// least [`MIN_ANCHOR`] bytes with [`MIN_DISTINCT_BYTES`] different ones. A rare window means few
/// false candidates, which is what a scan's speed is made of.
fn best_anchor(parts: &[Part]) -> Option<(usize, usize, usize)> {
    let mut best: Option<(f32, usize, usize, usize)> = None;
    for (index, part) in parts.iter().enumerate() {
        let Part::Bytes(bytes) = part else { continue };
        let mut start = 0;
        while start < bytes.len() {
            if bytes[start].is_none() {
                start += 1;
                continue;
            }
            let run: Vec<u8> = bytes[start..].iter().map_while(|byte| *byte).collect();
            if run.len() >= MIN_ANCHOR {
                let width = run.len().min(MAX_ANCHOR);
                for offset in 0..=run.len() - width {
                    let window = &run[offset..offset + width];
                    let mut distinct = [false; 256];
                    for &byte in window {
                        distinct[byte as usize] = true;
                    }
                    if distinct.iter().filter(|seen| **seen).count() < MIN_DISTINCT_BYTES {
                        continue;
                    }
                    let score = window_score(window);
                    if best.is_none_or(|(top, ..)| score > top) {
                        best = Some((score, index, start + offset, width));
                    }
                }
            }
            start += run.len();
        }
    }
    best.map(|(_, index, start, width)| (index, start, width))
}

/// How many pieces a logical signature may have.
const MAX_LOGICAL_SUBSIGNATURES: usize = 64;

/// Fixed bytes of a piece that may be wide: the zeros between characters say nothing.
fn fixed_bytes_narrow(signature: &Signature) -> usize {
    let bytes = fixed_bytes(signature);
    match signature.parts.first() {
        Some(Part::Bytes(run))
            if run.len() >= 2 && run.iter().skip(1).step_by(2).all(|b| *b == Some(0)) =>
        {
            bytes / 2
        }
        _ => bytes,
    }
}

fn fixed_bytes(signature: &Signature) -> usize {
    signature
        .parts
        .iter()
        .map(|part| match part {
            Part::Bytes(bytes) => bytes.iter().flatten().count(),
            Part::Gap { .. } => 0,
        })
        .sum()
}

/// `Target:1,FileSize:100-2000,Engine:51-255` into a target and a file size range. A key this
/// matcher does not model makes the signature unsupported: ignoring a condition would widen it.
fn parse_target_block(text: &str) -> Option<(Target, Option<(u64, u64)>)> {
    let mut target = None;
    let mut file_size = None;
    for entry in text.split(',') {
        let (key, value) = entry.split_once(':')?;
        match key.trim() {
            "Target" => {
                target = Some(match value.trim() {
                    "0" => Target::Any,
                    "1" => Target::Pe,
                    "2" => Target::Ole2,
                    "6" => Target::Elf,
                    "10" => Target::Pdf,
                    _ => return None,
                });
            }
            "FileSize" => {
                let (least, most) = value.trim().split_once('-')?;
                file_size = Some((least.parse().ok()?, most.parse().ok()?));
            }
            // The engine versions ClamAV signatures need are all older than this matcher.
            "Engine" => {}
            _ => return None,
        }
    }
    Some((target?, file_size))
}

/// One piece of a logical signature: `hex`, `offset:hex`, either followed by `::modifiers`.
/// Regular expressions and macros are not modelled. The modifiers `i` (either case), `w` (wide,
/// each byte followed by a zero), `a` (ascii, the default; with `w`, both) and `f` (fullword) are,
/// but only on a piece that is a plain run of bytes. A wide and ascii piece is two signatures.
fn parse_piece(name: &str, target: Target, text: &str) -> Result<Vec<Signature>, Parsed> {
    if text.is_empty() {
        return Err(Parsed::Unsupported("ldb: empty piece"));
    }
    if text.starts_with('/') {
        return Err(Parsed::Unsupported("ldb piece: regular expression"));
    }
    if text.contains('$') {
        return Err(Parsed::Unsupported("ldb piece: macro"));
    }
    let (body, modifiers) = match text.split_once("::") {
        Some((body, modifiers)) => (body, Some(modifiers)),
        None => (text, None),
    };
    let (offset, hex) = match body.split_once(':') {
        Some((offset, hex)) => match parse_offset(offset) {
            Some(offset) => (offset, hex),
            None => return Err(Parsed::Unsupported("ldb piece: offset form")),
        },
        None => (
            Offset {
                base: Base::Anywhere,
                shift: 0,
            },
            body,
        ),
    };
    if matches!(offset.base, Base::EntryPoint(_) | Base::Section { .. }) && target != Target::Pe {
        return Err(Parsed::Unsupported(
            "ldb piece: PE offset on a non-PE target",
        ));
    }
    let Some(modifiers) = modifiers else {
        return match build_signature(name, target, offset, hex, MIN_ANCHOR) {
            Parsed::Kept(signature) => Ok(vec![signature]),
            other => Err(other),
        };
    };

    let (mut fold, mut wide, mut ascii, mut fullword) = (false, false, false, false);
    for modifier in modifiers.chars() {
        match modifier {
            'i' => fold = true,
            'w' => wide = true,
            'a' => ascii = true,
            'f' => fullword = true,
            _ => {
                return Err(Parsed::Unsupported(
                    "ldb piece: modifier other than i, w, a, f",
                ))
            }
        }
    }
    if wide && fullword {
        return Err(Parsed::Unsupported("ldb piece: fullword on wide text"));
    }
    let literal = parse_literal(hex);
    if wide && literal.is_none() {
        return Err(Parsed::Unsupported(
            "ldb piece: wide modifier on a pattern with wildcards",
        ));
    }
    // Case folding and fullword work on any pattern: only wide needs plain bytes.
    let Some(literal) = literal else {
        return match build_signature(name, target, offset, hex, MIN_ANCHOR) {
            Parsed::Kept(mut signature) => {
                signature.fold = fold;
                signature.fullword = fullword;
                Ok(vec![signature])
            }
            other => Err(other),
        };
    };
    if literal.len() < MIN_ANCHOR {
        return Err(Parsed::TooWeak);
    }
    // `w` alone is wide only; `wa` is both; no `w` is ascii.
    let mut forms = Vec::new();
    if !wide || ascii {
        forms.push(literal.clone());
    }
    if wide {
        forms.push(literal.iter().flat_map(|byte| [*byte, 0]).collect());
    }
    let mut signatures = Vec::with_capacity(forms.len());
    for bytes in forms {
        let parts = vec![Part::Bytes(bytes.into_iter().map(Some).collect())];
        let Some((anchor_part, anchor_start, anchor_len)) = best_anchor(&parts) else {
            return Err(Parsed::TooWeak);
        };
        signatures.push(Signature {
            name: name.to_owned(),
            target,
            offset,
            parts,
            anchor_part,
            anchor_start,
            anchor_len,
            piece: false,
            fold,
            fullword,
        });
    }
    Ok(signatures)
}

/// Hex digits only: a plain run of bytes.
fn parse_literal(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > MAX_SIGNATURE_BYTES * 2 {
        return None;
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Why `parse_hex` refused `text`, for the report of what to build next.
fn hex_reason(text: &str) -> &'static str {
    if text.contains('!') {
        "hex: negated alternatives"
    } else if text.contains('(') {
        "hex: alternatives (a|b)"
    } else if text.contains('[') {
        "hex: byte-count ranges [n-m]"
    } else if text.contains('?') && !text.replace("??", "").contains('?') {
        "hex: other wildcard"
    } else if text.contains('?') {
        "hex: nibble wildcards (a?, ?a)"
    } else if text.contains('{') || text.contains('*') {
        "hex: gap form"
    } else {
        "hex: other"
    }
}

fn parse_offset(text: &str) -> Option<Offset> {
    let (position, shift) = match text.split_once(',') {
        Some((position, shift)) => (position, shift.parse().ok()?),
        None => (text, 0),
    };
    let base = if position == "*" {
        Base::Anywhere
    } else if let Some(distance) = position.strip_prefix("EOF-") {
        Base::FromEnd(distance.parse().ok()?)
    } else if let Some(delta) = position.strip_prefix("EP+") {
        Base::EntryPoint(delta.parse().ok()?)
    } else if let Some(delta) = position.strip_prefix("EP-") {
        Base::EntryPoint(-delta.parse::<isize>().ok()?)
    } else if let Some(delta) = position.strip_prefix("SL+") {
        Base::Section {
            index: None,
            delta: delta.parse().ok()?,
        }
    } else if let Some(rest) = position.strip_prefix('S') {
        let (index, delta) = rest.split_once('+')?;
        Base::Section {
            index: Some(index.parse().ok()?),
            delta: delta.parse().ok()?,
        }
    } else {
        Base::Absolute(position.parse().ok()?)
    };
    // `*` with a shift is meaningless, and a huge shift would make every position a candidate.
    if (base == Base::Anywhere && shift != 0) || shift > 1 << 16 {
        return None;
    }
    Some(Offset { base, shift })
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

fn bytes_match(pattern: &[Option<u8>], text: &[u8], fold: bool) -> bool {
    pattern.len() == text.len()
        && pattern.iter().zip(text).all(|(wanted, actual)| {
            wanted.is_none_or(|wanted| {
                wanted == *actual || (fold && wanted.eq_ignore_ascii_case(actual))
            })
        })
}

/// Whether the bytes just outside `start..end` are not letters or digits.
fn on_word_boundaries(text: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|index| text.get(index));
    let after = text.get(end);
    !before.is_some_and(u8::is_ascii_alphanumeric) && !after.is_some_and(u8::is_ascii_alphanumeric)
}

struct Context<'a> {
    text: &'a [u8],
    file_size: u64,
    truncated: bool,
    layout: &'a PeLayout,
}

/// Whether the whole signature matches with its anchor found at `anchor_at`.
fn verify(
    signature: &Signature,
    context: &Context<'_>,
    anchor_at: usize,
    steps: &mut usize,
) -> bool {
    let &Context {
        text,
        file_size,
        truncated,
        layout,
    } = context;
    let Part::Bytes(anchor_bytes) = &signature.parts[signature.anchor_part] else {
        return false;
    };
    let Some(part_start) = anchor_at.checked_sub(signature.anchor_start) else {
        return false;
    };
    let part_end = part_start + anchor_bytes.len();
    if part_end > text.len() {
        return false;
    }
    if !bytes_match(anchor_bytes, &text[part_start..part_end], signature.fold) {
        return false;
    }
    let before = &signature.parts[..signature.anchor_part];
    let after = &signature.parts[signature.anchor_part + 1..];
    let Some(start) = match_left(before, text, part_start, steps, signature.fold) else {
        return false;
    };
    let Some(end) = match_right(after, text, part_end, steps, signature.fold) else {
        return false;
    };
    if signature.fullword && !on_word_boundaries(text, start, end) {
        return false;
    }
    let offset = signature.offset;
    if offset.base == Base::Anywhere {
        return true;
    }
    // The end of a file is unknown when only its start was read.
    if matches!(offset.base, Base::FromEnd(_)) && (truncated || file_size as usize != text.len()) {
        return false;
    }
    let Some(first) = layout.resolve(offset.base, text.len()) else {
        return false;
    };
    end <= text.len() && (first..=first.saturating_add(offset.shift)).contains(&start)
}

/// Matches `parts` forward from `position`; returns where the match ends.
fn match_right(
    parts: &[Part],
    text: &[u8],
    position: usize,
    steps: &mut usize,
    fold: bool,
) -> Option<usize> {
    let Some((first, rest)) = parts.split_first() else {
        return Some(position);
    };
    match first {
        Part::Bytes(bytes) => {
            *steps += bytes.len();
            let end = position.checked_add(bytes.len())?;
            if *steps > MAX_VERIFY_STEPS
                || end > text.len()
                || !bytes_match(bytes, &text[position..end], fold)
            {
                return None;
            }
            match_right(rest, text, end, steps, fold)
        }
        Part::Gap { min, max } => {
            let limit = max.unwrap_or(MAX_UNBOUNDED_GAP).min(MAX_UNBOUNDED_GAP);
            for skip in *min..=limit {
                *steps += 1;
                if *steps > MAX_VERIFY_STEPS || position + skip > text.len() {
                    return None;
                }
                if let Some(end) = match_right(rest, text, position + skip, steps, fold) {
                    return Some(end);
                }
            }
            None
        }
    }
}

/// Matches `parts` backward from `end`; returns where the match starts.
fn match_left(
    parts: &[Part],
    text: &[u8],
    end: usize,
    steps: &mut usize,
    fold: bool,
) -> Option<usize> {
    let Some((last, rest)) = parts.split_last() else {
        return Some(end);
    };
    match last {
        Part::Bytes(bytes) => {
            *steps += bytes.len();
            let start = end.checked_sub(bytes.len())?;
            if *steps > MAX_VERIFY_STEPS || !bytes_match(bytes, &text[start..end], fold) {
                return None;
            }
            match_left(rest, text, start, steps, fold)
        }
        Part::Gap { min, max } => {
            let limit = max.unwrap_or(MAX_UNBOUNDED_GAP).min(MAX_UNBOUNDED_GAP);
            for skip in *min..=limit {
                *steps += 1;
                if *steps > MAX_VERIFY_STEPS {
                    return None;
                }
                let start = end.checked_sub(skip)?;
                if let Some(found) = match_left(rest, text, start, steps, fold) {
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

    fn set_of(lines: &[&str]) -> (PatternSet, PatternStats) {
        set(lines)
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

    /// A PE whose single section starts at file offset 0x400, with its entry point 0x10 bytes in.
    fn pe_with(entry_bytes: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x800];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // one section
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // optional header size
        let optional = 0x98;
        pe[optional + 16..optional + 20].copy_from_slice(&0x1010u32.to_le_bytes()); // entry rva
        let section = optional + 0xf0;
        pe[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
        pe[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        pe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        pe[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw pointer
        pe[0x410..0x410 + entry_bytes.len()].copy_from_slice(entry_bytes);
        pe
    }

    #[test]
    fn entry_point_and_section_offsets_follow_the_pe_layout() {
        let (set, stats) = set(&[
            "Win.Test.Ep:1:EP+0:cafebabe11223344",
            "Win.Test.EpBefore:1:EP-4:aabbccdd11223344",
            "Win.Test.EpShift:1:EP+0,8:0102030405060708",
            "Win.Test.Section:1:S0+16:cafebabe11223344",
            "Win.Test.Last:1:SL+16:cafebabe11223344",
            "Win.Test.WrongSection:1:S5+0:cafebabe11223344",
        ]);
        assert_eq!(stats.loaded, 6);
        let entry = [0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44];
        // Section 0 + 16 and the entry point are the same place, so three signatures agree; the
        // first loaded wins.
        assert_eq!(scan(&set, &pe_with(&entry)), Some("Win.Test.Ep"));

        // Four bytes before the entry point.
        let mut pe = pe_with(&[]);
        pe[0x40c..0x414].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(scan(&set, &pe), Some("Win.Test.EpBefore"));

        // Within the shift, and just outside it.
        let sequence = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut shifted = pe_with(&[]);
        shifted[0x418..0x420].copy_from_slice(&sequence);
        assert_eq!(scan(&set, &shifted), Some("Win.Test.EpShift"));
        let mut too_far = pe_with(&[]);
        too_far[0x419..0x421].copy_from_slice(&sequence);
        assert_eq!(scan(&set, &too_far), None);

        // The same bytes in the wrong place, or in a file that is not a PE.
        let mut elsewhere = pe_with(&[]);
        elsewhere[0x500..0x508].copy_from_slice(&entry);
        assert_eq!(scan(&set, &elsewhere), None);
        assert_eq!(scan(&set, &entry), None);
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
            "Unsupported.Offset:1:VI:11223344556677889900",
            "Unsupported.EpOutsidePe:0:EP+0:11223344556677889900",
            "Unsupported.Text:7:*:11223344556677889900",
            "garbage",
            "",
        ]);
        assert_eq!(stats.loaded, 0);
        assert_eq!(stats.too_weak, 2);
        assert_eq!(stats.unsupported, 7);
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

    fn logical_set(lines: &[&str]) -> (PatternSet, PatternStats) {
        let mut set = PatternSet::default();
        let mut stats = PatternStats::default();
        for line in lines {
            set.ingest_logical(line, &mut stats);
        }
        set.build();
        (set, stats)
    }

    fn document(parts: &[&[u8]]) -> Vec<u8> {
        let mut text = Vec::new();
        for part in parts {
            text.extend_from_slice(&[0x41; 20]);
            text.extend_from_slice(part);
        }
        text
    }

    #[test]
    fn a_logical_signature_needs_its_expression_to_hold() {
        let (set, stats) = logical_set(&[
            "Win.Test.Combo;Target:0;0&1&(2|3);aabbccddeeff;112233445566;556677889900;998877665544",
        ]);
        assert_eq!(stats.loaded, 1);
        let a: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let b: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let c: &[u8] = &[0x55, 0x66, 0x77, 0x88, 0x99, 0x00];
        let d: &[u8] = &[0x99, 0x88, 0x77, 0x66, 0x55, 0x44];
        assert_eq!(scan(&set, &document(&[a, b, c])), Some("Win.Test.Combo"));
        assert_eq!(scan(&set, &document(&[d, b, a])), Some("Win.Test.Combo"));
        // Missing a required piece, or neither of the alternatives.
        assert_eq!(scan(&set, &document(&[a, c])), None);
        assert_eq!(scan(&set, &document(&[a, b])), None);
        // A piece alone is never a detection.
        assert_eq!(scan(&set, &document(&[a])), None);
    }

    #[test]
    fn match_counts_and_file_size_are_honoured() {
        let (set, stats) = logical_set(&[
            "Win.Test.Repeated;Target:0;0>2&1;deadbeef01020304;cafebabe05060708",
            "Win.Test.Sized;Target:0,FileSize:100-200;0&1;0102030405060708;090a0b0c0d0e0f10",
        ]);
        assert_eq!(stats.loaded, 2);
        let dead: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];
        let cafe: &[u8] = &[0xca, 0xfe, 0xba, 0xbe, 5, 6, 7, 8];
        assert_eq!(
            scan(&set, &document(&[dead, dead, dead, cafe])),
            Some("Win.Test.Repeated")
        );
        assert_eq!(scan(&set, &document(&[dead, dead, cafe])), None);

        let one: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let two: &[u8] = &[9, 10, 11, 12, 13, 14, 15, 16];
        let mut inside = document(&[one, two]);
        inside.resize(150, 0x41);
        assert_eq!(scan(&set, &inside), Some("Win.Test.Sized"));
        let mut outside = document(&[one, two]);
        outside.resize(300, 0x41);
        assert_eq!(scan(&set, &outside), None);
    }

    #[test]
    fn pieces_can_carry_offsets() {
        let (set, _) =
            logical_set(&["Win.Test.Anchored;Target:0;0&1;0:4d5a900011223344;*:cafebabe05060708"]);
        let mut text = vec![0x4d, 0x5a, 0x90, 0x00, 0x11, 0x22, 0x33, 0x44];
        text.extend_from_slice(&[0x41; 30]);
        text.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 5, 6, 7, 8]);
        assert_eq!(scan(&set, &text), Some("Win.Test.Anchored"));
        let mut moved = vec![0x41];
        moved.extend_from_slice(&text);
        assert_eq!(scan(&set, &moved), None);
    }

    #[test]
    fn unmodelled_pieces_drop_the_whole_signature() {
        for line in [
            // A regular expression piece, a modifier, a macro, an alternative.
            "A;Target:0;0&1;aabbccdd;/evil.*payload/",
            "A;Target:0;0&1;aabbccdd;11223344::i",
            "A;Target:0;0&1;aabbccdd;${3-6}0$",
            "A;Target:0;0&1;aabbccdd;(11223344|55667788)",
            // A condition on the container.
            "A;Target:0,Container:CL_TYPE_ZIP;0&1;aabbccdd;11223344",
            // Mixed operators, or a piece the expression never uses.
            "A;Target:0;0&1|2;aabbccdd;11223344;55667788",
            "A;Target:0;0;aabbccdd;11223344",
            // Not enough fixed bytes in all.
            "A;Target:0;0&1;aabbccdd;11223344",
            "A;Target:0;0|1;aabbccdd;1122",
        ] {
            let (set, stats) = logical_set(&[line]);
            assert_eq!(stats.loaded, 0, "{line}");
            assert!(set.is_empty(), "{line}");
        }
        // Eight fixed bytes in all, but a single piece is held to the stand-alone rule.
        let (_, stats) = logical_set(&["A;Target:0;0;aabbccdd11223344"]);
        assert_eq!(stats.loaded, 1);
    }

    #[test]
    fn truncated_files_are_not_judged_by_logical_signatures() {
        let (set, _) = logical_set(&[
            "Win.Test.Neg;Target:0;0&1=0;aabbccddeeff00112233445566778899;deadbeefcafe",
        ]);
        let mut text = vec![0x41; 10];
        text.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        assert_eq!(
            set.scan(&text, text.len() as u64, false),
            Some("Win.Test.Neg")
        );
        // Only the start was read, so the second piece might be in the part not read.
        assert_eq!(set.scan(&text, text.len() as u64 + 100, true), None);
    }

    #[test]
    fn case_insensitive_wide_and_fullword_pieces() {
        // "evilpayload" in hex; the other piece anchors the combination.
        let evil = "6576696c7061796c6f6164";
        let (set, stats) = logical_set(&[
            &format!("Win.Test.Fold;Target:0;0&1;{evil}::i;aabbccddeeff1122"),
            &format!("Win.Test.Wide;Target:0;0&1;{evil}::w;1122334455667788"),
            &format!("Win.Test.Both;Target:0;0&1;{evil}::wa;8877665544332211"),
            &format!("Win.Test.Word;Target:0;0&1;{evil}::f;99aabbccddeeff00"),
        ]);
        assert_eq!(stats.loaded, 4);

        let with = |first: &[u8], second: &[u8]| {
            let mut text = vec![0x20u8; 6];
            text.extend_from_slice(first);
            text.extend_from_slice(&[0x20; 4]);
            text.extend_from_slice(second);
            text
        };
        let wide = |word: &str| word.bytes().flat_map(|byte| [byte, 0]).collect::<Vec<u8>>();
        let a: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        let b: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let c: &[u8] = &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let d: &[u8] = &[0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];

        // Either case, but ascii only.
        assert_eq!(scan(&set, &with(b"EvilPayLOAD", a)), Some("Win.Test.Fold"));
        assert_eq!(scan(&set, &with(&wide("evilpayload"), a)), None);
        // Wide only: the narrow text is not enough, the wide text is, and case matters.
        assert_eq!(
            scan(&set, &with(&wide("evilpayload"), b)),
            Some("Win.Test.Wide")
        );
        assert_eq!(scan(&set, &with(b"evilpayload", b)), None);
        assert_eq!(scan(&set, &with(&wide("EVILPAYLOAD"), b)), None);
        // Both forms.
        assert_eq!(scan(&set, &with(b"evilpayload", c)), Some("Win.Test.Both"));
        assert_eq!(
            scan(&set, &with(&wide("evilpayload"), c)),
            Some("Win.Test.Both")
        );
        // Fullword: a letter or digit on either side defeats it.
        assert_eq!(scan(&set, &with(b"evilpayload", d)), Some("Win.Test.Word"));
        assert_eq!(scan(&set, &with(b"xevilpayload", d)), None);
        assert_eq!(scan(&set, &with(b"evilpayload9", d)), None);
        assert_eq!(
            scan(&set, &with(b"-evilpayload.", d)),
            Some("Win.Test.Word")
        );
    }

    #[test]
    fn modifiers_on_anything_but_plain_bytes_are_refused() {
        for line in [
            // Wide text with wildcards, an unknown modifier, fullword on wide text, too short.
            "A;Target:0;0&1;aabb??ccddeeff::w;1122334455667788",
            "A;Target:0;0&1;aabbccddeeff0011::q;1122334455667788",
            "A;Target:0;0&1;aabbccddeeff0011::wf;1122334455667788",
            "A;Target:0;0&1;aabb::i;1122334455667788",
        ] {
            let (set, stats) = logical_set(&[line]);
            assert_eq!(stats.loaded, 0, "{line}");
            assert!(set.is_empty(), "{line}");
        }
    }

    #[test]
    fn case_folding_and_fullword_work_with_wildcards() {
        // "Evil" "Payload" with a one-byte wildcard between them, ignoring case.
        let (set, stats) = logical_set(&[
            "Win.Test.Folded;Target:0;0&1;6576696c??7061796c6f6164::i;aabbccddeeff1122",
        ]);
        assert_eq!(stats.loaded, 1);
        let with = |word: &[u8]| {
            let mut text = vec![0x20u8; 4];
            text.extend_from_slice(word);
            text.extend_from_slice(&[0x20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);
            text
        };
        assert_eq!(scan(&set, &with(b"EVIL_PAYLOAD")), Some("Win.Test.Folded"));
        assert_eq!(scan(&set, &with(b"evil-payload")), Some("Win.Test.Folded"));
        assert_eq!(scan(&set, &with(b"evil-paylaod")), None);
    }

    #[test]
    fn case_sensitive_signatures_stay_case_sensitive() {
        // "EvilPayload" with one automaton for everything: only the exact case convicts.
        let (set, _) = set(&["Win.Test.Case:0:*:4576696c5061796c6f6164"]);
        assert_eq!(scan(&set, b"..EvilPayload.."), Some("Win.Test.Case"));
        assert_eq!(scan(&set, b"..evilpayload.."), None);
        assert_eq!(scan(&set, b"..EVILPAYLOAD.."), None);
    }

    #[test]
    fn the_anchor_is_the_rarest_window_not_the_longest_run() {
        // Sixteen bytes of padding, then four rare ones: the padding must not be searched for.
        let line = "Win.Test.Padded:0:*:00000000000000000000000000000000deadbeef0102";
        let (set, stats) = set(&[line]);
        assert_eq!(stats.loaded, 1);
        let anchor = set.signatures[0].anchor();
        assert!(
            anchor.ends_with(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]),
            "{anchor:02x?}"
        );
        assert!(anchor.len() <= MAX_ANCHOR);
        // And it still matches whole.
        let mut text = vec![0u8; 16];
        text.extend_from_slice(&[0u8; 16]);
        text.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
        assert_eq!(scan(&set, &text), Some("Win.Test.Padded"));

        // Nothing but padding, stack setup or no-ops is too common to search for.
        let (set, stats) = set_of(&[
            "Win.Test.Zeros:0:*:0000000000000000000000000000000000",
            "Win.Test.Nops:0:*:90909090909090909090",
            "Win.Test.Prologue:0:*:558bec83ec10",
        ]);
        assert_eq!(stats.loaded, 0);
        assert!(set.is_empty());
    }

    #[test]
    fn scans_leave_no_counts_behind() {
        // The counters live in per-thread scratch that outlasts a scan and is shared by every set.
        let (first, _) =
            logical_set(&["Win.Test.A;Target:0;0&1;aabbccdd11223344;eeff00112233deadbeef"]);
        let (second, _) =
            logical_set(&["Win.Test.B;Target:0;0&1;aabbccdd11223344;99887766554433221100"]);
        let piece_a: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let piece_b: &[u8] = &[0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0xde, 0xad, 0xbe, 0xef];
        let piece_c: &[u8] = &[0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00];

        // A half match in one set must not complete with the other half seen in another scan.
        assert_eq!(scan(&first, &document(&[piece_a])), None);
        assert_eq!(scan(&first, &document(&[piece_b])), None);
        assert_eq!(scan(&second, &document(&[piece_c])), None);
        assert_eq!(scan(&second, &document(&[piece_a])), None);
        // And a full match still works afterwards, repeatedly.
        for _ in 0..3 {
            assert_eq!(
                scan(&first, &document(&[piece_a, piece_b])),
                Some("Win.Test.A")
            );
            assert_eq!(
                scan(&second, &document(&[piece_a, piece_c])),
                Some("Win.Test.B")
            );
            assert_eq!(scan(&first, &document(&[piece_b])), None);
        }
    }
}
