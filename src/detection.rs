use crate::amsi::{AmsiScanReport, AmsiScanner};
use crate::archive::{inspect_gzip, inspect_ole, inspect_zip, ContainerInspection};
use crate::clamdb::native_index::{IndexMatch, MatchOrigin, NativeIndex};
use crate::definitions::{DefinitionMatchRateCircuitBreaker, DefinitionMatchRateState};
use crate::engine::{ContentType, ScanEngine, ScanReport, Verdict as StaticVerdict};
use crate::rules::{RuleDisposition, RuleEnforcementAuthority, RuleEngine, RuleMatch};
use crate::similarity::{SimilarityEngine, SimilarityMatch};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionVerdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub verdict: DetectionVerdict,
    pub risk_score: u8,
    pub confidence: u8,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub bytes_scanned: usize,
    pub truncated: bool,
    pub analysis_completeness: crate::engine::AnalysisCompleteness,
    pub static_report: Option<ScanReport>,
    pub rule_matches: Vec<RuleMatch>,

    pub similarity_matches: Vec<SimilarityMatch>,

    pub container_inspection: Option<ContainerInspection>,

    pub amsi_report: Option<AmsiScanReport>,

    pub amsi_error: Option<String>,

    pub elapsed: Duration,
    pub from_cache: bool,
    pub error: Option<String>,

    pub automatic_quarantine_eligible: bool,

    pub execution_block_eligible: bool,
}

impl DetectionReport {
    pub fn should_quarantine(&self) -> bool {
        self.verdict == DetectionVerdict::Malicious && self.automatic_quarantine_eligible
    }

    pub fn should_block(&self) -> bool {
        self.execution_block_eligible
    }

    pub(crate) fn error(message: impl Into<String>, elapsed: Duration) -> Self {
        Self {
            verdict: DetectionVerdict::Error,
            risk_score: 0,
            confidence: 0,
            threat_name: None,
            sha256: None,
            file_size: 0,
            bytes_scanned: 0,
            truncated: false,
            analysis_completeness: crate::engine::AnalysisCompleteness::ResourceLimitReached,
            static_report: None,
            rule_matches: Vec::new(),
            similarity_matches: Vec::new(),
            container_inspection: None,
            amsi_report: None,
            amsi_error: None,
            elapsed,
            from_cache: false,
            error: Some(message.into()),
            automatic_quarantine_eligible: false,
            execution_block_eligible: false,
        }
    }

    pub(crate) fn ransomware_behavior(
        _distinct_files: usize,
        block: bool,
        elapsed: Duration,
    ) -> Self {
        Self {
            verdict: DetectionVerdict::Suspicious,
            risk_score: 95,
            confidence: 90,
            threat_name: Some("Behavior.Ransomware.MassModification".to_owned()),
            sha256: None,
            file_size: 0,
            bytes_scanned: 0,
            truncated: false,
            analysis_completeness: crate::engine::AnalysisCompleteness::Complete,
            static_report: None,
            rule_matches: Vec::new(),
            similarity_matches: Vec::new(),
            container_inspection: None,
            amsi_report: None,
            amsi_error: None,
            elapsed,
            from_cache: false,
            error: None,
            automatic_quarantine_eligible: false,
            execution_block_eligible: block,
        }
    }
}

/// Built-in rules that convict content submitted through AMSI; see `scan_amsi_submission`.
const AMSI_CONVICTING_RULES: &[&str] = &[
    "blackshard_powershell_obfuscated_download_execute",
    "blackshard_powershell_amsi_bypass_sequence",
    "blackshard_lolbin_remote_execution_command",
    "blackshard_office_macro_autoexec_shell_chain",
];

/// Whether a scan may hand content to the Windows AMSI for a second opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemAmsi {
    Consult,
    Skip,
}

pub struct DetectionEngine {
    static_engine: ScanEngine,
    rules: RuleEngine,
    similarity: SimilarityEngine,
    amsi: Option<Arc<AmsiScanner>>,
    amsi_initialization_error: Option<String>,
    external_rule_circuit_breaker: Mutex<DefinitionMatchRateCircuitBreaker>,
    external_similarity_circuit_breaker: Mutex<DefinitionMatchRateCircuitBreaker>,
    native_index: Arc<RwLock<NativeIndex>>,
}

impl DetectionEngine {
    pub fn new(static_engine: ScanEngine, rules: RuleEngine) -> Self {
        let (amsi, amsi_initialization_error) = match shared_system_amsi() {
            Ok(scanner) => (Some(scanner), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            static_engine,
            rules,
            similarity: SimilarityEngine::default(),
            amsi,
            amsi_initialization_error,
            external_rule_circuit_breaker: Mutex::new(DefinitionMatchRateCircuitBreaker::default()),
            external_similarity_circuit_breaker: Mutex::new(
                DefinitionMatchRateCircuitBreaker::default(),
            ),
            native_index: shared_native_index(),
        }
    }

    pub fn with_similarity(mut self, similarity: SimilarityEngine) -> Self {
        self.similarity = similarity;
        self
    }

    pub fn with_native_index(mut self, native_index: NativeIndex) -> Self {
        self.replace_native_index(native_index);
        self.native_index = shared_native_index();
        self
    }

    pub fn replace_native_index(&self, native_index: NativeIndex) {
        if let Ok(mut active) = self.native_index.write() {
            *active = native_index;
        }
    }

    /// Evaluates a sample against the natively parsed ClamAV hash databases.
    ///
    /// The whole file digests are only trustworthy when the static engine hashed the complete
    /// file, so a missing `sha256` (which it omits for truncated reads) skips the lookup entirely
    /// rather than risking a match against a prefix.
    fn evaluate_native_index(
        &self,
        sample: &[u8],
        static_report: &ScanReport,
        declared_size: u64,
        whole_file_md5: Option<[u8; 16]>,
    ) -> Option<IndexMatch> {
        let sha256: [u8; 32] = static_report
            .sha256
            .as_deref()
            .and_then(|value| hex::decode(value).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())?;

        self.native_index.read().ok().and_then(|index| {
            // Section digests only mean anything for a PE, and parsing is skipped otherwise.
            let sections = if matches!(
                static_report.content_type,
                ContentType::Pe32 | ContentType::Pe64 | ContentType::PeUnknown
            ) {
                index.section_digests(sample)
            } else {
                Vec::new()
            };
            index.evaluate(
                &sha256,
                whole_file_md5.as_ref(),
                Some(declared_size),
                &sections,
            )
        })
    }

    pub fn builtin() -> Result<Self, String> {
        Ok(Self::new(ScanEngine::default(), RuleEngine::builtin()?))
    }

    pub fn scan_path(&self, path: &Path) -> DetectionReport {
        let started = Instant::now();
        let symlink_metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not inspect {}: {error}", path.display()),
                    started.elapsed(),
                )
            }
        };
        if symlink_metadata.file_type().is_symlink() || !symlink_metadata.is_file() {
            return DetectionReport::error(
                format!("not a regular file: {}", path.display()),
                started.elapsed(),
            );
        }

        let file = match open_candidate_file(path) {
            Ok(file) => file,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not open {}: {error}", path.display()),
                    started.elapsed(),
                )
            }
        };
        self.scan_open_file(&file)
    }

    pub fn scan_open_file(&self, file: &File) -> DetectionReport {
        contain_panics(Instant::now(), || self.analyze_open_file(file))
    }

    fn analyze_open_file(&self, file: &File) -> DetectionReport {
        let started = Instant::now();
        let change_time_before = opened_change_time(file);
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => {
                return DetectionReport::error(
                    "the opened candidate is not a regular file",
                    started.elapsed(),
                )
            }
            Err(error) => {
                return DetectionReport::error(
                    format!("could not inspect the opened candidate: {error}"),
                    started.elapsed(),
                )
            }
        };
        let mut reader = match file.try_clone() {
            Ok(reader) => reader,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not duplicate the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        if let Err(error) = reader.seek(SeekFrom::Start(0)) {
            return DetectionReport::error(
                format!("could not seek the candidate handle: {error}"),
                started.elapsed(),
            );
        }
        let sample_limit = self.static_engine.config().max_read_bytes;
        let with_md5 = self
            .native_index
            .read()
            .is_ok_and(|index| index.wants_file_md5(before.len()));
        let (sample, digests) = match read_and_hash(&mut reader, sample_limit, with_md5) {
            Ok(result) => result,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not read the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        let after = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not revalidate the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        // Length and mtime miss a same-size rewrite that lands in the same mtime tick or sets the
        // mtime back. The change time moves on every write, so it catches those as well.
        if before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || change_time_before != opened_change_time(file)
        {
            return DetectionReport::error(
                "the opened file changed while it was being analyzed",
                started.elapsed(),
            );
        }

        let declared_size = before.len().max(digests.length);
        let static_start = Instant::now();
        let static_report =
            self.static_engine
                .scan_sample_with_digest(&sample, declared_size, digests.sha256);
        let static_duration = static_start.elapsed();

        let native_index_start = Instant::now();
        let native_index_match =
            self.evaluate_native_index(&sample, &static_report, declared_size, digests.md5);
        let native_index_duration = native_index_start.elapsed();

        let yara_start = Instant::now();
        let (rule_matches, rule_failure) = self.scan_rules(&sample);
        let yara_duration = yara_start.elapsed();

        let ml_start = Instant::now();
        let similarity_matches =
            self.apply_similarity_circuit_breaker(self.similarity.scan(&sample, declared_size));
        let ml_duration = ml_start.elapsed();

        let amsi_start = Instant::now();
        let (amsi_report, amsi_error) = self.scan_with_amsi(&static_report, &rule_matches, &sample);
        let amsi_duration = amsi_start.elapsed();

        log::debug!(
            "EvidenceCascade metrics: Static: {:?}, ClamDb: {:?}, YARA: {:?}, Similarity: {:?}, AMSI: {:?}",
            static_duration, native_index_duration, yara_duration, ml_duration, amsi_duration
        );

        let cascade = EvidenceCascade {
            learned_shard: learned_shard(&static_report),
            static_report,
            native_index_match,
            rule_matches,
            similarity_matches,
            amsi_report,
            amsi_error,
        };

        let mut report = cascade.resolve(started.elapsed());
        record_rule_failure(&mut report, rule_failure);
        self.with_container_inspection(&sample, report, started, SystemAmsi::Consult)
    }

    pub fn scan_bytes(&self, bytes: &[u8]) -> DetectionReport {
        self.scan_bytes_with(bytes, SystemAmsi::Consult)
    }

    /// Scans content that reached the service *through* AMSI, from blackshard's own provider.
    ///
    /// Windows has already dispatched that content to every registered AMSI provider, so handing
    /// it back to the system AMSI would be redundant. It would also recurse: the system AMSI calls
    /// blackshard's provider, which calls this service, which calls the system AMSI again, each
    /// level holding a pipe instance until they run out and the innermost call fails open.
    ///
    /// Content arriving here is about to run, already deobfuscated, so the built-in rules that
    /// describe what a script *does* convict it. On disk the same rules only raise suspicion,
    /// because documentation, research notes and detection rules quote the same strings.
    pub fn scan_amsi_submission(&self, bytes: &[u8]) -> DetectionReport {
        let mut report = self.scan_bytes_with(bytes, SystemAmsi::Skip);
        if matches!(
            report.verdict,
            DetectionVerdict::Clean | DetectionVerdict::Suspicious
        ) {
            if let Some(rule) = report.rule_matches.iter().find(|matched| {
                matched.namespace == "blackshard_builtin"
                    && AMSI_CONVICTING_RULES.contains(&matched.identifier.as_str())
            }) {
                report.threat_name = Some(format!(
                    "AMSI.{}",
                    rule.threat_name
                        .strip_prefix("Suspicious.")
                        .unwrap_or(&rule.threat_name)
                ));
                report.verdict = DetectionVerdict::Malicious;
                report.risk_score = report.risk_score.max(95);
                report.confidence = report.confidence.max(95);
            }
        }
        report
    }

    fn scan_bytes_with(&self, bytes: &[u8], system_amsi: SystemAmsi) -> DetectionReport {
        let started = Instant::now();
        contain_panics(started, || {
            let report = self.scan_leaf_bytes_with(bytes, system_amsi);
            self.with_container_inspection(bytes, report, started, system_amsi)
        })
    }

    #[cfg(test)]
    pub(crate) fn scan_leaf_bytes(&self, bytes: &[u8]) -> DetectionReport {
        self.scan_leaf_bytes_with(bytes, SystemAmsi::Consult)
    }

    fn scan_leaf_bytes_with(&self, bytes: &[u8], system_amsi: SystemAmsi) -> DetectionReport {
        let started = Instant::now();
        let static_start = Instant::now();
        let static_report = self.static_engine.scan_bytes(bytes);
        let static_duration = static_start.elapsed();

        let native_index_start = Instant::now();
        let native_index_match = self.evaluate_native_index(
            bytes,
            &static_report,
            bytes.len() as u64,
            Some(Md5::digest(bytes).into()),
        );
        let native_index_duration = native_index_start.elapsed();

        let yara_start = Instant::now();
        let (rule_matches, rule_failure) = self.scan_rules(bytes);
        let yara_duration = yara_start.elapsed();

        let ml_start = Instant::now();
        let similarity_matches =
            self.apply_similarity_circuit_breaker(self.similarity.scan(bytes, bytes.len() as u64));
        let ml_duration = ml_start.elapsed();

        let amsi_start = Instant::now();
        let (amsi_report, amsi_error) = match system_amsi {
            SystemAmsi::Consult => self.scan_with_amsi(&static_report, &rule_matches, bytes),
            SystemAmsi::Skip => (None, None),
        };
        let amsi_duration = amsi_start.elapsed();

        log::debug!(
            "EvidenceCascade metrics (leaf): Static: {:?}, ClamDb: {:?}, YARA: {:?}, Similarity: {:?}, AMSI: {:?}",
            static_duration, native_index_duration, yara_duration, ml_duration, amsi_duration
        );

        let cascade = EvidenceCascade {
            learned_shard: learned_shard(&static_report),
            static_report,
            native_index_match,
            rule_matches,
            similarity_matches,
            amsi_report,
            amsi_error,
        };
        let mut report = cascade.resolve(started.elapsed());
        record_rule_failure(&mut report, rule_failure);
        report
    }

    /// Runs the YARA rules. A failure, usually the per-scan timeout on a large file, yields no rule
    /// matches rather than ending the analysis: everything else the cascade knows still counts.
    /// Ending it turned a hash conviction into a scan error, which real-time protection allows, so
    /// padding a known sample until YARA gave up was enough to run it.
    fn scan_rules(&self, bytes: &[u8]) -> (Vec<RuleMatch>, Option<String>) {
        match self.rules.scan(bytes) {
            Ok(matches) => (self.apply_external_rule_circuit_breaker(matches), None),
            Err(error) => (Vec::new(), Some(error)),
        }
    }

    fn with_container_inspection(
        &self,
        bytes: &[u8],
        mut report: DetectionReport,
        started: Instant,
        system_amsi: SystemAmsi,
    ) -> DetectionReport {
        let content_type = report
            .static_report
            .as_ref()
            .map(|static_report| static_report.content_type);
        if report.truncated
            || !matches!(
                content_type,
                Some(ContentType::Zip | ContentType::Gzip | ContentType::OleCompound)
            )
        {
            report.elapsed = started.elapsed();
            return report;
        }

        let inspection = match content_type {
            Some(ContentType::Zip) => {
                inspect_zip(bytes, |entry| self.scan_leaf_bytes_with(entry, system_amsi))
            }
            Some(ContentType::OleCompound) => {
                inspect_ole(bytes, |entry| self.scan_leaf_bytes_with(entry, system_amsi))
            }
            Some(ContentType::Gzip) => {
                inspect_gzip(bytes, |entry| self.scan_leaf_bytes_with(entry, system_amsi))
            }
            _ => unreachable!("container type was checked above"),
        };
        let strongest = inspection
            .findings
            .iter()
            .max_by_key(|finding| (finding.verdict_rank(), finding.risk_score));
        if let Some(finding) = strongest {
            match finding.verdict {
                DetectionVerdict::Malicious => {
                    report.verdict = DetectionVerdict::Malicious;
                    report.risk_score = report.risk_score.max(finding.risk_score);
                    report.confidence = report.confidence.max(95);
                }
                DetectionVerdict::Suspicious if report.verdict == DetectionVerdict::Clean => {
                    report.verdict = DetectionVerdict::Suspicious;
                    report.risk_score = report.risk_score.max(finding.risk_score);
                    report.confidence = report.confidence.max(80);
                }
                DetectionVerdict::Error
                | DetectionVerdict::Clean
                | DetectionVerdict::Suspicious => {}
            }
            if report.threat_name.is_none() || finding.verdict == DetectionVerdict::Malicious {
                let nested_name = finding
                    .threat_name
                    .as_deref()
                    .unwrap_or("Suspicious.EmbeddedObject");
                report.threat_name = Some(format!("Container.Contains.{nested_name}"));
            }
            report.automatic_quarantine_eligible |= finding.automatic_quarantine_eligible
                && report.sha256.is_some()
                && !report.truncated;
            report.execution_block_eligible |=
                finding.execution_block_eligible || report.automatic_quarantine_eligible;
        }

        let structural_risk = inspection.structural_risk_score();
        if structural_risk >= 55 && report.verdict == DetectionVerdict::Clean {
            report.verdict = DetectionVerdict::Suspicious;
            report.risk_score = structural_risk;
            report.confidence = 75;
            report.threat_name = Some(if inspection.limit_triggered {
                "Archive.ResourceLimitTriggered".to_owned()
            } else {
                "Office.MacroWithExternalContent".to_owned()
            });
        }
        if inspection.incomplete
            && report.analysis_completeness == crate::engine::AnalysisCompleteness::Complete
        {
            // Part of the container went unread, so a clean result says less than it seems to.
            report.analysis_completeness =
                crate::engine::AnalysisCompleteness::ResourceLimitReached;
        }
        report.container_inspection = Some(inspection);
        report.elapsed = started.elapsed();
        report
    }

    fn scan_with_amsi(
        &self,
        static_report: &ScanReport,
        rule_matches: &[RuleMatch],
        sample: &[u8],
    ) -> (Option<AmsiScanReport>, Option<String>) {
        let eligible = matches!(
            static_report.content_type,
            ContentType::Script(_) | ContentType::OleCompound
        ) || !rule_matches.is_empty();
        if !eligible {
            return (None, None);
        }
        let Some(scanner) = &self.amsi else {
            return (None, self.amsi_initialization_error.clone());
        };
        match scanner.scan_buffer(sample, "Blackshard.FileContent") {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        }
    }

    pub fn external_rules_tripped(&self) -> bool {
        let rules_tripped = self
            .external_rule_circuit_breaker
            .lock()
            .map(|breaker| breaker.is_tripped())
            .unwrap_or(true);
        let similarity_tripped = self
            .external_similarity_circuit_breaker
            .lock()
            .map(|breaker| breaker.is_tripped())
            .unwrap_or(true);
        rules_tripped || similarity_tripped
    }

    fn apply_external_rule_circuit_breaker(&self, mut matches: Vec<RuleMatch>) -> Vec<RuleMatch> {
        let external_match = matches
            .iter()
            .any(|matched| matched.namespace != "blackshard_builtin");
        let tripped = self
            .external_rule_circuit_breaker
            .lock()
            .map(|mut breaker| {
                matches!(
                    breaker.observe_external_match(external_match),
                    DefinitionMatchRateState::Tripped { .. }
                )
            })
            .unwrap_or(true);
        if tripped {
            matches.retain(|matched| matched.namespace == "blackshard_builtin");
        }
        matches
    }

    fn apply_similarity_circuit_breaker(
        &self,
        mut matches: Vec<SimilarityMatch>,
    ) -> Vec<SimilarityMatch> {
        let external_match = !matches.is_empty();
        let tripped = self
            .external_similarity_circuit_breaker
            .lock()
            .map(|mut breaker| {
                matches!(
                    breaker.observe_external_match(external_match),
                    DefinitionMatchRateState::Tripped { .. }
                )
            })
            .unwrap_or(true);
        if tripped {
            matches.clear();
        }
        matches
    }
}

/// Digests of an entire file, however large.
struct WholeFileDigests {
    sha256: [u8; 32],
    /// Only computed when the native index could use it; see `NativeIndex::wants_file_md5`.
    md5: Option<[u8; 16]>,
    length: u64,
}

/// Reads the whole file once: the first `limit` bytes are kept for analysis, and every byte goes
/// through the hashers.
///
/// Analysis is what is expensive, and it stays bounded. Hashing is cheap, so it covers the whole
/// file, and a known sample padded past the analysis limit is still recognised by its digest.
fn read_and_hash(
    reader: &mut impl Read,
    limit: usize,
    with_md5: bool,
) -> io::Result<(Vec<u8>, WholeFileDigests)> {
    let mut sample = Vec::with_capacity(limit.min(1024 * 1024));
    let mut sha256 = Sha256::new();
    let mut md5 = with_md5.then(Md5::new);
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut length = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let chunk = &buffer[..read];
        sha256.update(chunk);
        if let Some(md5) = md5.as_mut() {
            md5.update(chunk);
        }
        let room = limit.saturating_sub(sample.len());
        sample.extend_from_slice(&chunk[..read.min(room)]);
        length += read as u64;
    }
    Ok((
        sample,
        WholeFileDigests {
            sha256: sha256.finalize().into(),
            md5: md5.map(|md5| md5.finalize().into()),
            length,
        },
    ))
}

/// Runs one analysis, turning a panic anywhere in it into an error verdict.
///
/// Every parser here is memory-safe Rust working on a bounded sample, so what malformed input can
/// realistically cause is a panic, not memory corruption. Containing it keeps one bad file from
/// killing the scanning thread, and with it real-time protection.
///
/// ponytail: no hang protection. A parser stuck in a loop holds its thread until the service
/// restarts; an out-of-process worker pool with per-request timeouts is the upgrade, and becomes
/// necessary if a parser written in an unsafe language (libclamav, say) is ever linked in.
fn contain_panics(started: Instant, analysis: impl FnOnce() -> DetectionReport) -> DetectionReport {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(analysis)).unwrap_or_else(|_| {
        DetectionReport::error("the analysis panicked on this input", started.elapsed())
    })
}

#[cfg(windows)]
pub(crate) fn open_candidate_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
pub(crate) fn open_candidate_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
pub(crate) fn opened_file_id(file: &File) -> io::Result<u64> {
    Ok(opened_file_identity(file)?.file_id)
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpenedFileIdentity {
    pub file_id: u64,
    pub volume_serial_number: u32,
    pub link_count: u32,
}

#[cfg(windows)]
pub(crate) fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: isize,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as isize, information.as_mut_ptr())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok(OpenedFileIdentity {
        file_id: ((information.file_index_high as u64) << 32) | information.file_index_low as u64,
        volume_serial_number: information.volume_serial_number,
        link_count: information.number_of_links,
    })
}

/// The file's change time (`FILE_BASIC_INFO::ChangeTime`), which the file system moves on every
/// content or metadata change, including the mapped and kernel-mode writes the driver's generation
/// counter misses. `None` when it cannot be read; callers then compare `None == None`, which is
/// no worse than not checking it.
#[cfg(windows)]
pub(crate) fn opened_change_time(file: &File) -> Option<i64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO,
    };

    let mut information = std::mem::MaybeUninit::<FILE_BASIC_INFO>::uninit();
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileBasicInfo,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    (read != 0).then(|| unsafe { information.assume_init() }.ChangeTime)
}

#[cfg(not(windows))]
pub(crate) fn opened_change_time(_file: &File) -> Option<i64> {
    None
}

#[cfg(not(windows))]
pub(crate) fn opened_file_id(_file: &File) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable Windows file identity is unavailable on this platform",
    ))
}

pub struct EvidenceCascade {
    pub static_report: ScanReport,
    /// A hit from the natively parsed ClamAV hash databases, if any.
    pub native_index_match: Option<IndexMatch>,
    /// The threat name of a shard this machine learned for the file's digest, if any.
    pub learned_shard: Option<String>,
    pub rule_matches: Vec<RuleMatch>,
    pub similarity_matches: Vec<SimilarityMatch>,
    pub amsi_report: Option<AmsiScanReport>,
    pub amsi_error: Option<String>,
}

impl EvidenceCascade {
    pub fn resolve(self, elapsed: Duration) -> DetectionReport {
        // `sha256` is only ever the digest of the entire file, so an exact match convicts the file
        // itself even when the rest of the analysis was bounded to a prefix. Every conviction that
        // names this file, by its whole digest or by a ClamAV section digest, removes it: blocking
        // only its execution would leave a live sample on disk for the next double-click, archive
        // tool or copy. Quarantine is encrypted and restorable, so a false positive costs a click.
        // Rule, similarity and AMSI verdicts describe content rather than identify a file, and
        // the historical reputation corpus carries mis-submitted benign files, so those only block.
        let automatic_quarantine_eligible = self.static_report.sha256.is_some()
            && ((self.static_report.verdict == StaticVerdict::Malicious
                && self
                    .static_report
                    .evidence
                    .iter()
                    .any(|evidence| evidence.code == "signature.exact_sha256"))
                || self.native_index_match.is_some()
                || self.learned_shard.is_some());
        let reputation_block_eligible = self.static_report.verdict == StaticVerdict::Malicious
            && self.static_report.sha256.is_some()
            && self
                .static_report
                .evidence
                .iter()
                .any(|evidence| evidence.code == "signature.reputation_sha256");

        let malicious_rule = self
            .rule_matches
            .iter()
            .filter(|item| item.disposition == RuleDisposition::Malicious)
            .max_by_key(|item| item.risk_score);
        let suspicious_rule_score = self
            .rule_matches
            .iter()
            .filter(|item| item.disposition == RuleDisposition::Suspicious)
            .map(|item| item.risk_score)
            .max()
            .unwrap_or(0);
        let similarity_score = self
            .similarity_matches
            .iter()
            .map(|matched| {
                82u8.saturating_add(
                    ((matched.similarity_basis_points.saturating_sub(8_500)) / 125) as u8,
                )
                .min(94)
            })
            .max()
            .unwrap_or(0);

        let amsi_provider_detection = self
            .amsi_report
            .as_ref()
            .is_some_and(AmsiScanReport::is_provider_detection);
        let amsi_policy_block = self
            .amsi_report
            .as_ref()
            .is_some_and(AmsiScanReport::should_block_execution);

        let mut block_eligible =
            automatic_quarantine_eligible || reputation_block_eligible || amsi_policy_block;
        let mut threat_name = None;
        let mut confidence = self.static_report.confidence;
        let mut risk_score = self.static_report.risk_score;
        let mut verdict = DetectionVerdict::Clean;

        if self.static_report.verdict == StaticVerdict::Malicious {
            verdict = DetectionVerdict::Malicious;
            risk_score = 100;
            confidence = confidence.max(99);
            threat_name = Some("Known.Malware.ExactSignature".to_owned());
            block_eligible = true;
        } else if let Some(matched) = self.native_index_match {
            verdict = DetectionVerdict::Malicious;
            // A whole file digest identifies one exact sample. A section digest is a slightly
            // weaker claim, because a section can in principle be shared with benign code, so it
            // convicts at the same tier the ClamAV sidecar used to occupy.
            let (score, certainty) = match matched.origin {
                MatchOrigin::WholeFile => (100, 100),
                MatchOrigin::PeSection => (95, 95),
            };
            risk_score = score;
            confidence = certainty;
            threat_name = Some(matched.threat_name);
            block_eligible = true;
        } else if let Some(name) = self.learned_shard.clone() {
            verdict = DetectionVerdict::Malicious;
            risk_score = 100;
            confidence = 100;
            threat_name = Some(name);
            block_eligible = true;
        } else if amsi_provider_detection {
            verdict = DetectionVerdict::Malicious;
            risk_score = 99;
            confidence = 99;
            threat_name = Some("AMSI.Provider.MalwareDetected".to_owned());
            block_eligible = true;
        } else if let Some(rule) = malicious_rule {
            verdict = DetectionVerdict::Malicious;
            risk_score = rule.risk_score.max(95);
            confidence = 99;
            threat_name = Some(rule.threat_name.clone());
            block_eligible = rule.enforcement_authority == RuleEnforcementAuthority::ExecutionDeny;
        } else if amsi_policy_block {
            verdict = DetectionVerdict::Suspicious;
            risk_score = 90;
            confidence = 99;
            threat_name = Some("AMSI.Policy.BlockedByAdministrator".to_owned());
        } else if self.static_report.verdict == StaticVerdict::Error {
            verdict = DetectionVerdict::Error;
            risk_score = 0;
            confidence = 0;
            threat_name = None;
        } else if self.static_report.verdict == StaticVerdict::Suspicious
            || suspicious_rule_score > 0
            || similarity_score > 0
        {
            let independent_bonus = if self.static_report.verdict == StaticVerdict::Suspicious
                && suspicious_rule_score > 0
            {
                10
            } else {
                0
            };

            verdict = DetectionVerdict::Suspicious;
            risk_score = self
                .static_report
                .risk_score
                .max(suspicious_rule_score)
                .max(similarity_score)
                .saturating_add(independent_bonus)
                .min(99);
            confidence = self.static_report.confidence.max(75);

            threat_name = self
                .rule_matches
                .iter()
                .filter(|item| item.disposition == RuleDisposition::Suspicious)
                .max_by_key(|item| item.risk_score)
                .map(|item| item.threat_name.clone())
                .or_else(|| {
                    self.similarity_matches
                        .first()
                        .map(|matched| matched.threat_name.clone())
                })
                .or_else(|| Some("Suspicious.StaticAnalysis".to_owned()));

            if similarity_score > 0
                && suspicious_rule_score == 0
                && self.static_report.verdict == StaticVerdict::Clean
            {
                log::info!(
                    "Similarity shadow mode: hold for deeper analysis. Threat: {:?}",
                    threat_name
                );
            }
        }

        DetectionReport {
            verdict,
            risk_score,
            confidence,
            threat_name,
            sha256: self.static_report.sha256.clone(),
            file_size: self.static_report.file_size,
            bytes_scanned: self.static_report.bytes_scanned,
            truncated: self.static_report.truncated,
            analysis_completeness: self.static_report.analysis_completeness,
            error: self.static_report.error.clone(),
            static_report: Some(self.static_report),
            rule_matches: self.rule_matches,
            similarity_matches: self.similarity_matches,
            container_inspection: None,
            amsi_report: self.amsi_report,
            amsi_error: self.amsi_error,
            elapsed,
            from_cache: false,
            automatic_quarantine_eligible,
            execution_block_eligible: block_eligible,
        }
    }
}

/// Marks a report whose rules did not finish, so its verdict is never cached or treated as a
/// complete clean bill of health.
fn record_rule_failure(report: &mut DetectionReport, failure: Option<String>) {
    if let Some(failure) = failure {
        report.analysis_completeness = crate::engine::AnalysisCompleteness::TimedOut;
        report.error.get_or_insert(failure);
    }
}

fn learned_shard(static_report: &ScanReport) -> Option<String> {
    static_report
        .sha256
        .as_deref()
        .and_then(crate::shards::lookup)
}

fn shared_native_index() -> Arc<RwLock<NativeIndex>> {
    static SHARED: OnceLock<Arc<RwLock<NativeIndex>>> = OnceLock::new();
    Arc::clone(SHARED.get_or_init(|| Arc::new(RwLock::new(NativeIndex::new()))))
}

fn shared_system_amsi() -> Result<Arc<AmsiScanner>, String> {
    static SHARED: OnceLock<Result<Arc<AmsiScanner>, String>> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            AmsiScanner::new(crate::ipc::SERVICE_AMSI_APP_NAME)
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_analysis_becomes_an_error_verdict() {
        let report = contain_panics(Instant::now(), || panic!("malformed input"));
        assert_eq!(report.verdict, DetectionVerdict::Error);
        assert!(!report.should_block() && !report.should_quarantine());
    }
    #[test]
    fn whole_file_digests_cover_bytes_past_the_analysis_limit() {
        let mut file = vec![7u8; 5000];
        file[4999] = 9;
        let (sample, digests) = read_and_hash(&mut file.as_slice(), 1000, true).unwrap();

        assert_eq!(sample.len(), 1000);
        assert_eq!(digests.length, 5000);
        assert_eq!(digests.sha256, <[u8; 32]>::from(Sha256::digest(&file)));
        assert_eq!(digests.md5, Some(<[u8; 16]>::from(Md5::digest(&file))));

        let (_, without_md5) = read_and_hash(&mut file.as_slice(), 1000, false).unwrap();
        assert!(without_md5.md5.is_none());
    }

    #[test]
    fn a_padded_file_reports_the_digest_of_every_byte() {
        let engine = DetectionEngine::new(
            ScanEngine::new(
                crate::engine::ScanConfig {
                    max_read_bytes: 16,
                    ..Default::default()
                },
                crate::engine::SignatureDatabase::default(),
            )
            .unwrap(),
            RuleEngine::builtin().unwrap(),
        );
        let mut padded = crate::self_test::PAYLOAD.to_vec();
        padded.resize(4096, 0);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("padded.bin");
        fs::write(&path, &padded).unwrap();
        let report = engine.scan_path(&path);

        // The analysed prefix is 16 bytes, but the digest is of all 4096.
        assert!(report.truncated);
        assert_eq!(
            report.sha256.as_deref(),
            Some(hex::encode(Sha256::digest(&padded)).as_str())
        );
    }

    #[test]
    fn harmless_self_test_is_malicious_and_quarantinable() {
        let engine = DetectionEngine::builtin().unwrap();
        let report = engine.scan_bytes(crate::self_test::PAYLOAD);
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_quarantine());
        assert!(report.automatic_quarantine_eligible);
        assert_eq!(report.risk_score, 100);
    }

    #[test]
    fn entropy_alone_remains_clean() {
        let engine = DetectionEngine::builtin().unwrap();
        let bytes = (0u8..=255).cycle().take(1024 * 1024).collect::<Vec<_>>();
        let report = engine.scan_bytes(&bytes);
        assert_eq!(report.verdict, DetectionVerdict::Clean);
        assert!(!report.should_quarantine());
    }

    #[test]
    fn path_scans_are_not_reused_from_a_metadata_only_cache() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("clean.txt");
        fs::write(&path, b"ordinary text document").unwrap();
        let engine = DetectionEngine::builtin().unwrap();
        let first = engine.scan_path(&path);
        let second = engine.scan_path(&path);
        assert_eq!(first.verdict, DetectionVerdict::Clean);
        assert!(!first.from_cache);
        assert!(!second.from_cache);
    }

    #[test]
    fn exact_open_handle_can_be_scanned_without_reopening_a_path() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("candidate.txt");
        fs::write(&path, b"ordinary text document").unwrap();
        let file = open_candidate_file(&path).unwrap();
        fs::rename(&path, temporary.path().join("renamed.txt")).unwrap();
        let report = DetectionEngine::builtin().unwrap().scan_open_file(&file);
        assert_eq!(report.verdict, DetectionVerdict::Clean);
    }

    #[test]
    fn amsi_provider_detection_blocks_but_never_authorizes_quarantine() {
        let static_report = ScanEngine::default().scan_bytes(b"ordinary script-like bytes");
        let cascade = EvidenceCascade {
            static_report,
            native_index_match: None,
            learned_shard: None,
            rule_matches: Vec::new(),
            similarity_matches: Vec::new(),
            amsi_report: Some(AmsiScanReport::synthetic(0x8000, 26, false)),
            amsi_error: None,
        };
        let report = cascade.resolve(Duration::ZERO);
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_block());
        assert!(!report.should_quarantine());
        assert!(!report.automatic_quarantine_eligible);
    }

    fn cascade(native_index_match: Option<IndexMatch>, learned: Option<&str>) -> DetectionReport {
        EvidenceCascade {
            static_report: ScanEngine::default().scan_bytes(b"an ordinary file body"),
            native_index_match,
            learned_shard: learned.map(str::to_owned),
            rule_matches: Vec::new(),
            similarity_matches: Vec::new(),
            amsi_report: None,
            amsi_error: None,
        }
        .resolve(Duration::ZERO)
    }

    #[test]
    fn a_section_signature_blocks_and_quarantines_the_file() {
        let report = cascade(
            Some(IndexMatch {
                threat_name: "Win.Trojan.Section".to_owned(),
                origin: MatchOrigin::PeSection,
            }),
            None,
        );
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_block() && report.should_quarantine());
    }

    #[test]
    fn a_learned_shard_blocks_and_quarantines_the_file() {
        let report = cascade(None, Some("Shard.Behavior.Ransomware"));
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert_eq!(
            report.threat_name.as_deref(),
            Some("Shard.Behavior.Ransomware")
        );
        assert!(report.should_block() && report.should_quarantine());
    }

    #[test]
    fn a_file_whose_digest_was_learned_is_convicted_on_sight() {
        let body = b"blackshard learned-shard detection test body 7f3c";
        let digest = hex::encode(Sha256::digest(body));
        crate::shards::learn(&digest, "Shard.Test.Detection").unwrap();
        let report = DetectionEngine::builtin().unwrap().scan_bytes(body);
        crate::shards::forget(&digest).unwrap();
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_quarantine());
    }

    #[test]
    fn an_amsi_bypass_is_refused_at_runtime_but_only_suspicious_on_disk() {
        let script = b"$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');
            $a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
            # AmsiScanBuffer VirtualProtect";
        let engine = DetectionEngine::builtin().unwrap();
        let on_disk = engine.scan_bytes(script);
        assert_ne!(on_disk.verdict, DetectionVerdict::Malicious);
        let at_runtime = engine.scan_amsi_submission(script);
        assert_eq!(at_runtime.verdict, DetectionVerdict::Malicious);
        assert_eq!(
            at_runtime.threat_name.as_deref(),
            Some("AMSI.PowerShell.AMSIBypass")
        );
        assert!(!at_runtime.should_quarantine());
    }

    #[test]
    fn ordinary_scripts_pass_amsi() {
        let engine = DetectionEngine::builtin().unwrap();
        let report = engine.scan_amsi_submission(b"Get-ChildItem $env:TEMP | Measure-Object");
        assert_eq!(report.verdict, DetectionVerdict::Clean);
    }

    #[test]
    fn a_rule_timeout_does_not_discard_a_hash_conviction() {
        // A sample the exact-hash list knows, scanned by rules that cannot finish in time.
        let rules = RuleEngine::compile(&[crate::rules::RuleBundle {
            namespace: "slow".to_owned(),
            source: r#"rule slow { condition: for all i in (0..400000000) : (uint8(i % filesize) != 7) }"#
                .to_owned(),
            policies: Vec::new(),
        }])
        .unwrap();
        let engine = DetectionEngine::new(ScanEngine::default(), rules);
        let report = engine.scan_bytes(crate::self_test::PAYLOAD);
        assert_eq!(
            report.verdict,
            DetectionVerdict::Malicious,
            "{:?}",
            report.error
        );
        assert!(report.should_block() && report.should_quarantine());
        assert_eq!(
            report.analysis_completeness,
            crate::engine::AnalysisCompleteness::TimedOut
        );
    }
}
