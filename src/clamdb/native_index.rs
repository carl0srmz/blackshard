//! Native reader for the ClamAV signature databases blackshard consumes directly.
//!
//! The hash families are handled here directly, and `.ndb` body signatures and `.ldb` logical
//! signatures through the matcher in [`super::pattern`]. Bytecode is not evaluated yet:
//!
//! | Extension       | Layout                               | Meaning                       |
//! |-----------------|--------------------------------------|-------------------------------|
//! | `.hdb` / `.hdu` | `MD5:FileSize:Name`                  | whole file MD5                |
//! | `.hsb` / `.hsu` | `SHA:FileSize:Name`                  | whole file SHA-256            |
//! | `.mdb` / `.mdu` | `PESectionSize:MD5:Name`             | PE section MD5                |
//! | `.msb` / `.msu` | `PESectionSize:SHA256:Name`          | PE section SHA-256            |
//! | `.ndb`          | `Name:Target:Offset:HexSignature`    | byte pattern in the file      |
//! | `.ldb`          | `Name;Target;Expression;Sub;Sub...`  | several patterns and a rule   |
//! | `.fp`           | `MD5:FileSize:Name`                  | allowlist, suppresses matches |
//! | `.sfp`          | `SHA:FileSize:Name`                  | allowlist, suppresses matches |
//!
//! Note that the section families put the size *first*; this is a genuine quirk of the format and
//! not a transcription error. A size of `*` matches any size.
//!
//! The `u`-suffixed variants hold potentially unwanted applications and are only loaded when the
//! caller opts in, since convicting PUA by default produces false positives on legitimate software.

use md5::Md5;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// Longest line accepted from a database file, guarding against a corrupt or hostile feed.
const MAX_LINE_BYTES: usize = 16 * 1024;

/// A single hash signature. `size` of `None` corresponds to the `*` wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry<const N: usize> {
    pub hash: [u8; N],
    pub size: Option<u64>,
    pub name: String,
}

/// A sorted, binary searchable table of fixed width digests.
#[derive(Debug, Clone)]
pub struct HashTable<const N: usize> {
    entries: Vec<HashEntry<N>>,
}

impl<const N: usize> Default for HashTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HashTable<N> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn push(&mut self, hash: [u8; N], size: Option<u64>, name: String) {
        self.entries.push(HashEntry { hash, size, name });
    }

    fn sort(&mut self) {
        self.entries.sort_by_key(|entry| entry.hash);
    }

    /// Returns the threat name recorded for `hash`, provided the declared size also matches.
    pub fn lookup(&self, hash: &[u8; N], size: Option<u64>) -> Option<&str> {
        let found = self
            .entries
            .binary_search_by(|entry| entry.hash.cmp(hash))
            .ok()?;

        // Several signatures may share a digest while pinning different sizes, so walk outwards
        // from the hit until the digest changes.
        let mut low = found;
        while low > 0 && self.entries[low - 1].hash == *hash {
            low -= 1;
        }
        self.entries[low..]
            .iter()
            .take_while(|entry| entry.hash == *hash)
            .find(|entry| size_matches(entry.size, size))
            .map(|entry| entry.name.as_str())
    }
}

fn size_matches(signature_size: Option<u64>, subject_size: Option<u64>) -> bool {
    match (signature_size, subject_size) {
        // A `*` wildcard in the signature matches regardless of what the subject reports.
        (None, _) => true,
        (Some(expected), Some(actual)) => expected == actual,
        // The signature pins a size but the subject's is unknown, so it cannot be confirmed.
        (Some(_), None) => false,
    }
}

/// The digests of one PE section, used to query the `.mdb` and `.msb` families.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionDigest {
    pub size: u64,
    pub md5: [u8; 16],
    pub sha256: [u8; 32],
}

/// A detection produced by the native index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexMatch {
    pub threat_name: String,
    pub origin: MatchOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOrigin {
    /// A whole file digest matched.
    WholeFile,
    /// An individual PE section digest matched, which also catches repacked variants.
    PeSection,
    /// A byte pattern matched inside the file, which catches a family rather than one sample.
    Pattern,
}

/// Every hash family blackshard loads out of an unpacked ClamAV database directory.
#[derive(Debug, Clone, Default)]
pub struct NativeIndex {
    file_sha256: HashTable<32>,
    file_md5: HashTable<16>,
    section_sha256: HashTable<32>,
    section_md5: HashTable<16>,
    allow_sha256: HashSet<[u8; 32]>,
    allow_md5: HashSet<[u8; 16]>,
    /// File sizes named by whole-file MD5 signatures and MD5 allowlist entries, so a caller can
    /// skip hashing a large file with MD5 when no MD5 entry could possibly match it.
    md5_sizes: HashSet<u64>,
    /// Set when some MD5 entry uses the `*` size wildcard, which could match a file of any size.
    md5_any_size: bool,
    /// Section sizes named by section signatures, so only sections that could match are hashed.
    section_sizes: HashSet<u64>,
    /// Set when some section signature uses the `*` size wildcard.
    section_any_size: bool,
    patterns: super::pattern::PatternSet,
}

/// Which database families a load should consider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Include the `u`-suffixed potentially unwanted application databases. Off by default, since
    /// convicting PUA without the user asking produces false positives on legitimate software.
    pub include_pua: bool,
}

/// How many signatures a load added, broken down by family.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadStats {
    pub file_hashes: usize,
    pub section_hashes: usize,
    pub allowlist_entries: usize,
    /// `.ndb` body signatures kept.
    pub patterns: usize,
    /// `.ndb` lines that use features the matcher does not model, or are too weak to convict on.
    pub patterns_skipped: usize,
    /// How many of the skipped lines each unmodelled feature accounts for.
    pub pattern_skip_reasons: std::collections::BTreeMap<&'static str, usize>,
}

impl LoadStats {
    pub fn total(&self) -> usize {
        self.file_hashes + self.section_hashes + self.allowlist_entries + self.patterns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    FileHash,
    SectionHash,
    Allowlist,
}

impl NativeIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of convicting signatures held, excluding allowlist entries.
    pub fn len(&self) -> usize {
        self.file_sha256.len()
            + self.file_md5.len()
            + self.section_sha256.len()
            + self.section_md5.len()
            + self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn allowlist_len(&self) -> usize {
        self.allow_sha256.len() + self.allow_md5.len()
    }

    /// Loads every recognised database file beneath `root`.
    pub fn load_from_directory<P: AsRef<Path>>(
        &mut self,
        root: P,
        options: LoadOptions,
    ) -> io::Result<LoadStats> {
        let mut stats = LoadStats::default();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .max_depth(3)
            .into_iter()
        {
            let entry = entry.map_err(io::Error::other)?;
            if !entry.file_type().is_file() {
                continue;
            }
            let Some(extension) = entry.path().extension().and_then(|value| value.to_str()) else {
                continue;
            };
            let extension = extension.to_ascii_lowercase();
            if !options.include_pua && extension.ends_with('u') && extension != "sfp" {
                continue;
            }
            let added = self.load_file(entry.path(), false)?;
            stats.file_hashes += added.file_hashes;
            stats.section_hashes += added.section_hashes;
            stats.allowlist_entries += added.allowlist_entries;
            stats.patterns += added.patterns;
            stats.patterns_skipped += added.patterns_skipped;
            for (reason, count) in added.pattern_skip_reasons {
                *stats.pattern_skip_reasons.entry(reason).or_default() += count;
            }
        }
        self.sort();
        self.patterns.build();
        Ok(stats)
    }

    /// Loads one database file, dispatching on its extension.
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<LoadStats> {
        self.load_file(path.as_ref(), true)
    }

    /// `finish` says whether this is the last file of a load, so the pattern automaton is built
    /// now rather than by the directory walk that called it.
    fn load_file(&mut self, path: &Path, finish: bool) -> io::Result<LoadStats> {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if matches!(extension.as_str(), "ndb" | "ldb" | "ldu" | "ndu") {
            let stats = self.load_patterns(path, extension.starts_with('l'))?;
            if finish {
                self.patterns.build();
            }
            return Ok(stats);
        }

        let (family, hash_first) = match extension.as_str() {
            "hdb" | "hdu" | "hsb" | "hsu" => (Family::FileHash, true),
            "mdb" | "mdu" | "msb" | "msu" => (Family::SectionHash, false),
            "fp" | "sfp" => (Family::Allowlist, true),
            _ => return Ok(LoadStats::default()),
        };

        let mut stats = LoadStats::default();
        let reader = BufReader::new(File::open(path)?);
        for line in reader.lines() {
            let line = line?;
            if line.len() > MAX_LINE_BYTES {
                continue;
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if self.ingest(line, family, hash_first) {
                match family {
                    Family::FileHash => stats.file_hashes += 1,
                    Family::SectionHash => stats.section_hashes += 1,
                    Family::Allowlist => stats.allowlist_entries += 1,
                }
            }
        }
        Ok(stats)
    }

    fn load_patterns(&mut self, path: &Path, logical: bool) -> io::Result<LoadStats> {
        let mut pattern_stats = super::pattern::PatternStats::default();
        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;
            if line.len() > MAX_LINE_BYTES {
                pattern_stats.unsupported += 1;
                continue;
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if logical {
                self.patterns.ingest_logical(line, &mut pattern_stats);
            } else {
                self.patterns.ingest(line, &mut pattern_stats);
            }
        }
        Ok(LoadStats {
            patterns: pattern_stats.loaded,
            patterns_skipped: pattern_stats.unsupported + pattern_stats.too_weak,
            pattern_skip_reasons: {
                let mut reasons = pattern_stats.reasons;
                if pattern_stats.too_weak > 0 {
                    reasons.insert("too few fixed bytes to convict on", pattern_stats.too_weak);
                }
                reasons
            },
            ..LoadStats::default()
        })
    }

    /// Looks for a body signature in `sample`, the start of a file of `file_size` bytes. Files
    /// vouched for by the allowlists are never convicted.
    pub fn evaluate_patterns(
        &self,
        sample: &[u8],
        file_size: u64,
        sha256: &[u8; 32],
        md5: Option<&[u8; 16]>,
    ) -> Option<IndexMatch> {
        if self.patterns.is_empty() || self.is_allowlisted(sha256, md5) {
            return None;
        }
        let truncated = file_size > sample.len() as u64;
        self.patterns
            .scan(sample, file_size, truncated)
            .map(|name| IndexMatch {
                threat_name: name.to_owned(),
                origin: MatchOrigin::Pattern,
            })
    }

    /// Parses one signature line. Returns whether it was understood and stored.
    ///
    /// `hash_first` distinguishes the whole file families (`hash:size:name`) from the PE section
    /// families, which invert the first two fields (`size:hash:name`).
    fn ingest(&mut self, line: &str, family: Family, hash_first: bool) -> bool {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            return false;
        }
        let (hash_text, size_text) = if hash_first {
            (parts[0], parts[1])
        } else {
            (parts[1], parts[0])
        };
        let name = parts[2].trim();
        if name.is_empty() {
            return false;
        }

        let size = if size_text.trim() == "*" {
            None
        } else {
            match size_text.trim().parse::<u64>() {
                Ok(value) => Some(value),
                Err(_) => return false,
            }
        };

        let Ok(bytes) = hex::decode(hash_text.trim()) else {
            return false;
        };

        match (family, bytes.len()) {
            (Family::FileHash, 32) => {
                let hash: [u8; 32] = bytes.try_into().expect("length checked above");
                self.file_sha256.push(hash, size, name.to_owned());
                true
            }
            (Family::FileHash, 16) => {
                let hash: [u8; 16] = bytes.try_into().expect("length checked above");
                self.file_md5.push(hash, size, name.to_owned());
                self.note_md5_size(size);
                true
            }
            (Family::SectionHash, 32) => {
                let hash: [u8; 32] = bytes.try_into().expect("length checked above");
                self.section_sha256.push(hash, size, name.to_owned());
                self.note_section_size(size);
                true
            }
            (Family::SectionHash, 16) => {
                let hash: [u8; 16] = bytes.try_into().expect("length checked above");
                self.section_md5.push(hash, size, name.to_owned());
                self.note_section_size(size);
                true
            }
            (Family::Allowlist, 32) => {
                self.allow_sha256
                    .insert(bytes.try_into().expect("length checked above"));
                true
            }
            (Family::Allowlist, 16) => {
                self.allow_md5
                    .insert(bytes.try_into().expect("length checked above"));
                self.note_md5_size(size);
                true
            }
            // SHA-1 signatures also appear in `.hsb`; blackshard does not compute SHA-1, so they
            // are skipped rather than stored where they could never match.
            _ => false,
        }
    }

    fn note_md5_size(&mut self, size: Option<u64>) {
        match size {
            Some(size) => {
                self.md5_sizes.insert(size);
            }
            None => self.md5_any_size = true,
        }
    }

    fn note_section_size(&mut self, size: Option<u64>) {
        match size {
            Some(size) => {
                self.section_sizes.insert(size);
            }
            None => self.section_any_size = true,
        }
    }

    /// The digests of the PE sections in `bytes` that a section signature could match.
    ///
    /// Hashing every section of every executable twice was the costliest part of a lookup, and
    /// usually for nothing: with no section signatures loaded nothing is parsed at all, and
    /// otherwise only sections of a size some signature names are hashed.
    pub fn section_digests(&self, bytes: &[u8]) -> Vec<SectionDigest> {
        if self.section_sha256.is_empty() && self.section_md5.is_empty() {
            return Vec::new();
        }
        section_digests_where(bytes, |size| {
            self.section_any_size || self.section_sizes.contains(&size)
        })
    }

    /// Whether a whole-file MD5 of a file this size could match anything in the index.
    ///
    /// MD5 is the slower of the two digests, and for a multi-gigabyte file it dominates the scan,
    /// so callers only compute it when this says it can matter.
    pub fn wants_file_md5(&self, file_size: u64) -> bool {
        self.md5_any_size || self.md5_sizes.contains(&file_size)
    }

    fn sort(&mut self) {
        self.file_sha256.sort();
        self.file_md5.sort();
        self.section_sha256.sort();
        self.section_md5.sort();
    }

    /// True when ClamAV's own false positive lists vouch for this file.
    pub fn is_allowlisted(&self, sha256: &[u8; 32], md5: Option<&[u8; 16]>) -> bool {
        self.allow_sha256.contains(sha256)
            || md5.is_some_and(|digest| self.allow_md5.contains(digest))
    }

    /// Evaluates a whole file digest against the hash databases.
    ///
    /// Retained for callers that only have a SHA-256 to hand; prefer [`NativeIndex::evaluate`],
    /// which also consults the section databases and the allowlists.
    pub fn evaluate_sha256(&self, sha256: &[u8], file_size: Option<u64>) -> Option<&str> {
        let hash: [u8; 32] = sha256.try_into().ok()?;
        if self.allow_sha256.contains(&hash) {
            return None;
        }
        self.file_sha256.lookup(&hash, file_size)
    }

    /// Full evaluation of one sample.
    ///
    /// The allowlists are consulted first and short circuit everything else, so a file vouched for
    /// by ClamAV's own false positive lists can never be convicted here. Whole file hashes are
    /// checked before section hashes because they are the more specific claim.
    pub fn evaluate(
        &self,
        sha256: &[u8; 32],
        md5: Option<&[u8; 16]>,
        file_size: Option<u64>,
        sections: &[SectionDigest],
    ) -> Option<IndexMatch> {
        if self.is_allowlisted(sha256, md5) {
            return None;
        }

        if let Some(name) = self.file_sha256.lookup(sha256, file_size) {
            return Some(IndexMatch {
                threat_name: name.to_owned(),
                origin: MatchOrigin::WholeFile,
            });
        }
        if let Some(name) = md5.and_then(|md5| self.file_md5.lookup(md5, file_size)) {
            return Some(IndexMatch {
                threat_name: name.to_owned(),
                origin: MatchOrigin::WholeFile,
            });
        }

        for section in sections {
            let size = Some(section.size);
            if let Some(name) = self.section_sha256.lookup(&section.sha256, size) {
                return Some(IndexMatch {
                    threat_name: name.to_owned(),
                    origin: MatchOrigin::PeSection,
                });
            }
            if let Some(name) = self.section_md5.lookup(&section.md5, size) {
                return Some(IndexMatch {
                    threat_name: name.to_owned(),
                    origin: MatchOrigin::PeSection,
                });
            }
        }

        None
    }
}

/// Computes the MD5 and SHA-256 of every PE section present in `bytes`.
///
/// Sections whose declared extent falls outside the buffer are skipped, so a truncated or
/// malformed sample simply yields fewer digests rather than an error. Zero length sections carry
/// no distinguishing content and are ignored.
pub fn pe_section_digests(bytes: &[u8]) -> Vec<SectionDigest> {
    section_digests_where(bytes, |_| true)
}

fn section_digests_where(bytes: &[u8], wanted: impl Fn(u64) -> bool) -> Vec<SectionDigest> {
    let Ok(pe) = goblin::pe::PE::parse(bytes) else {
        return Vec::new();
    };

    let mut digests = Vec::new();
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let length = section.size_of_raw_data as usize;
        if length == 0 || !wanted(length as u64) {
            continue;
        }
        let Some(end) = start.checked_add(length) else {
            continue;
        };
        let Some(body) = bytes.get(start..end) else {
            continue;
        };
        digests.push(SectionDigest {
            size: length as u64,
            md5: Md5::digest(body).into(),
            sha256: Sha256::digest(body).into(),
        });
    }
    digests
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(directory: &Path, name: &str, contents: &str) {
        let mut file = File::create(directory.join(name)).unwrap();
        writeln!(file, "{contents}").unwrap();
    }

    fn sha(byte: &str) -> [u8; 32] {
        hex::decode(byte.repeat(32)).unwrap().try_into().unwrap()
    }

    fn md5(byte: &str) -> [u8; 16] {
        hex::decode(byte.repeat(16)).unwrap().try_into().unwrap()
    }

    #[test]
    fn body_signatures_load_match_and_respect_the_allowlist() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "main.ndb",
            "Win.Test.Family:0:*:deadbeef00112233\nUnsupported.Sig:7:*:11223344556677889900",
        );
        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!((stats.patterns, stats.patterns_skipped), (1, 1));
        assert_eq!(index.len(), 1);

        let sample = [0u8, 0, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 9];
        let digest = sha("ab");
        let matched = index
            .evaluate_patterns(&sample, sample.len() as u64, &digest, None)
            .expect("pattern should match");
        assert_eq!(matched.threat_name, "Win.Test.Family");
        assert_eq!(matched.origin, MatchOrigin::Pattern);
        assert!(index
            .evaluate_patterns(&[0u8; 64], 64, &digest, None)
            .is_none());

        // A file ClamAV vouches for is never convicted by a pattern.
        write(
            directory.path(),
            "daily.fp",
            &format!("{}:11:Allowed", "ab".repeat(16)),
        );
        let mut vouched = NativeIndex::new();
        vouched
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert!(vouched
            .evaluate_patterns(&sample, sample.len() as u64, &digest, Some(&md5("ab")))
            .is_none());
    }

    #[test]
    fn logical_signatures_load_and_match_across_files() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.ldb",
            "Win.Test.Logical;Target:0;0&1;deadbeef00112233;cafebabe44556677\n\
             Win.Test.Regex;Target:0;0&1;deadbeef00112233;/evil.*regex/",
        );
        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!((stats.patterns, stats.patterns_skipped), (1, 1));

        let mut sample = vec![0x41u8; 8];
        sample.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
        sample.extend_from_slice(&[0x41; 8]);
        let digest = sha("ab");
        assert!(index
            .evaluate_patterns(&sample, sample.len() as u64, &digest, None)
            .is_none());
        sample.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0x44, 0x55, 0x66, 0x77]);
        let matched = index
            .evaluate_patterns(&sample, sample.len() as u64, &digest, None)
            .expect("both pieces are present");
        assert_eq!(matched.threat_name, "Win.Test.Logical");
        assert_eq!(matched.origin, MatchOrigin::Pattern);
    }

    #[test]
    fn loads_whole_file_sha256_and_md5_databases() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:4:Test.Sha", "11".repeat(32)),
        );
        write(
            directory.path(),
            "main.hdb",
            &format!("{}:4:Test.Md5", "22".repeat(16)),
        );

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(stats.file_hashes, 2);

        let matched = index
            .evaluate(&sha("11"), Some(&md5("ff")), Some(4), &[])
            .unwrap();
        assert_eq!(matched.threat_name, "Test.Sha");
        assert_eq!(matched.origin, MatchOrigin::WholeFile);

        let matched = index
            .evaluate(&sha("ff"), Some(&md5("22")), Some(4), &[])
            .unwrap();
        assert_eq!(matched.threat_name, "Test.Md5");
    }

    #[test]
    fn section_databases_put_the_size_before_the_hash() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.msb",
            &format!("512:{}:Test.Section", "33".repeat(32)),
        );
        write(
            directory.path(),
            "daily.mdb",
            &format!("256:{}:Test.SectionMd5", "44".repeat(16)),
        );

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(stats.section_hashes, 2);

        let sections = vec![SectionDigest {
            size: 512,
            md5: md5("00"),
            sha256: sha("33"),
        }];
        let matched = index
            .evaluate(&sha("ee"), Some(&md5("ee")), Some(9_999), &sections)
            .unwrap();
        assert_eq!(matched.threat_name, "Test.Section");
        assert_eq!(matched.origin, MatchOrigin::PeSection);

        let sections = vec![SectionDigest {
            size: 256,
            md5: md5("44"),
            sha256: sha("00"),
        }];
        assert_eq!(
            index
                .evaluate(&sha("ee"), Some(&md5("ee")), Some(9_999), &sections)
                .unwrap()
                .threat_name,
            "Test.SectionMd5"
        );
    }

    #[test]
    fn a_section_signature_does_not_fire_when_the_section_size_differs() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.msb",
            &format!("512:{}:Test.Section", "33".repeat(32)),
        );

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();

        let sections = vec![SectionDigest {
            size: 4_096,
            md5: md5("00"),
            sha256: sha("33"),
        }];
        assert!(index
            .evaluate(&sha("ee"), Some(&md5("ee")), Some(9_999), &sections)
            .is_none());
    }

    #[test]
    fn allowlists_suppress_a_matching_signature() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:4:Test.Sha", "11".repeat(32)),
        );
        write(
            directory.path(),
            "daily.sfp",
            &format!("{}:4:Vendor.Allowlisted", "11".repeat(32)),
        );

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(stats.allowlist_entries, 1);
        assert_eq!(index.allowlist_len(), 1);

        assert!(index
            .evaluate(&sha("11"), Some(&md5("ff")), Some(4), &[])
            .is_none());
        assert!(index.evaluate_sha256(&sha("11"), Some(4)).is_none());
    }

    #[test]
    fn an_md5_allowlist_entry_also_suppresses_a_sha256_signature() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:4:Test.Sha", "11".repeat(32)),
        );
        write(
            directory.path(),
            "daily.fp",
            &format!("{}:4:Vendor.Allowlisted", "22".repeat(16)),
        );

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();

        assert!(index
            .evaluate(&sha("11"), Some(&md5("22")), Some(4), &[])
            .is_none());
        assert!(index
            .evaluate(&sha("11"), Some(&md5("ff")), Some(4), &[])
            .is_some());
    }

    #[test]
    fn wildcard_sizes_match_any_subject() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:*:Test.AnySize", "11".repeat(32)),
        );

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();

        assert!(index
            .evaluate(&sha("11"), Some(&md5("ff")), Some(1), &[])
            .is_some());
        assert!(index
            .evaluate(&sha("11"), Some(&md5("ff")), None, &[])
            .is_some());
    }

    #[test]
    fn pua_databases_are_excluded_unless_requested() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsu",
            &format!("{}:4:Pua.Adware", "55".repeat(32)),
        );

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(stats.file_hashes, 0);

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions { include_pua: true })
            .unwrap();
        assert_eq!(stats.file_hashes, 1);
    }

    #[test]
    fn unrelated_and_malformed_lines_are_ignored() {
        let directory = tempfile::tempdir().unwrap();
        write(directory.path(), "daily.ldb", "logical;signature;body");
        write(directory.path(), "notes.txt", "irrelevant");
        let mut file = File::create(directory.path().join("daily.hsb")).unwrap();
        writeln!(file, "# a comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "nothex:4:Bad.Hex").unwrap();
        writeln!(file, "{}:notanumber:Bad.Size", "11".repeat(32)).unwrap();
        writeln!(file, "{}:4:Missing.Nothing", "11".repeat(20)).unwrap();
        writeln!(file, "{}:4:Good.One", "11".repeat(32)).unwrap();

        let mut index = NativeIndex::new();
        let stats = index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(stats.file_hashes, 1);
        assert_eq!(
            index
                .evaluate(&sha("11"), Some(&md5("ff")), Some(4), &[])
                .unwrap()
                .threat_name,
            "Good.One"
        );
    }

    #[test]
    fn threat_names_containing_colons_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:4:Win.Trojan:Agent-1", "11".repeat(32)),
        );

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(
            index
                .evaluate(&sha("11"), Some(&md5("ff")), Some(4), &[])
                .unwrap()
                .threat_name,
            "Win.Trojan:Agent-1"
        );
    }

    #[test]
    fn signatures_sharing_a_digest_but_pinning_different_sizes_both_resolve() {
        let directory = tempfile::tempdir().unwrap();
        let digest = "11".repeat(32);
        let mut file = File::create(directory.path().join("daily.hsb")).unwrap();
        writeln!(file, "{digest}:10:Test.Ten").unwrap();
        writeln!(file, "{digest}:20:Test.Twenty").unwrap();
        writeln!(file, "{digest}:30:Test.Thirty").unwrap();

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();

        for (size, expected) in [(10, "Test.Ten"), (20, "Test.Twenty"), (30, "Test.Thirty")] {
            assert_eq!(
                index
                    .evaluate(&sha("11"), Some(&md5("ff")), Some(size), &[])
                    .unwrap()
                    .threat_name,
                expected
            );
        }
        assert!(index
            .evaluate(&sha("11"), Some(&md5("ff")), Some(40), &[])
            .is_none());
    }

    /// Builds a 64 bit PE with a single 0x1000 byte section starting at file offset 0x200.
    fn minimal_pe(section_body: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());

        let section = optional + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        bytes[0x200..0x1200].fill(section_body);
        bytes
    }

    #[test]
    fn pe_section_digests_cover_each_section_body() {
        let digests = pe_section_digests(&minimal_pe(0xc3));
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].size, 0x1000);
        assert_eq!(
            digests[0].sha256,
            Sha256::digest([0xc3u8; 0x1000]).as_slice()
        );
        assert_eq!(digests[0].md5, Md5::digest([0xc3u8; 0x1000]).as_slice());
    }

    #[test]
    fn only_sections_a_signature_could_match_are_hashed() {
        let sample = minimal_pe(0xc3);
        assert!(NativeIndex::new().section_digests(&sample).is_empty());

        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.mdb",
            &format!("512:{}:Test.OtherSize", "44".repeat(16)),
        );
        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert!(index.section_digests(&sample).is_empty());

        write(
            directory.path(),
            "main.mdb",
            &format!("{}:{}:Test.ThisSize", 0x1000, "55".repeat(16)),
        );
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(index.section_digests(&sample), pe_section_digests(&sample));
    }

    #[test]
    fn a_repacked_variant_is_caught_by_its_section_hash() {
        let original = minimal_pe(0xc3);
        let section = pe_section_digests(&original).remove(0);

        // The section body is unchanged but the file as a whole is not, which is exactly the case
        // whole file hashing misses and section hashing is meant to catch.
        let mut repacked = original.clone();
        repacked.extend_from_slice(b"appended packer stub");
        assert_ne!(
            Sha256::digest(&original).as_slice(),
            Sha256::digest(&repacked).as_slice()
        );

        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.msb",
            &format!(
                "{}:{}:Test.Repacked",
                section.size,
                hex::encode(section.sha256)
            ),
        );
        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();

        let matched = index
            .evaluate(
                &Sha256::digest(&repacked).into(),
                Some(&Md5::digest(&repacked).into()),
                Some(repacked.len() as u64),
                &index.section_digests(&repacked),
            )
            .unwrap();
        assert_eq!(matched.threat_name, "Test.Repacked");
        assert_eq!(matched.origin, MatchOrigin::PeSection);
    }

    #[test]
    fn md5_is_only_wanted_for_sizes_an_md5_entry_names() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "main.hdb",
            &format!("{}:4096:Test.Md5", "22".repeat(16)),
        );
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:*:Test.Sha", "11".repeat(32)),
        );

        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert!(index.wants_file_md5(4096));
        // A SHA-256 wildcard does not make MD5 worth computing.
        assert!(!index.wants_file_md5(5 * 1024 * 1024 * 1024));

        write(
            directory.path(),
            "daily.fp",
            &format!("{}:*:Vendor.Clean", "33".repeat(16)),
        );
        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert!(index.wants_file_md5(5 * 1024 * 1024 * 1024));
    }

    #[test]
    fn a_missing_md5_still_allows_sha256_and_section_matches() {
        let directory = tempfile::tempdir().unwrap();
        write(
            directory.path(),
            "daily.hsb",
            &format!("{}:4:Test.Sha", "11".repeat(32)),
        );
        let mut index = NativeIndex::new();
        index
            .load_from_directory(directory.path(), LoadOptions::default())
            .unwrap();
        assert_eq!(
            index
                .evaluate(&sha("11"), None, Some(4), &[])
                .unwrap()
                .threat_name,
            "Test.Sha"
        );
    }

    #[test]
    fn pe_section_digests_are_empty_for_a_non_pe_sample() {
        assert!(pe_section_digests(b"not an executable at all").is_empty());
    }
}
