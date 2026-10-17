use crate::detection::{DetectionReport, DetectionVerdict};
use crate::vba;
use flate2::read::MultiGzDecoder;
use std::io::{Cursor, Read};
use std::time::{Duration, Instant};
use zip::ZipArchive;

const MAX_ARCHIVE_DEPTH: u8 = 3;
const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_EXPANDED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_ENTRY_NAME_CHARS: usize = 512;
const MAX_FINDINGS: usize = 32;
const MAX_INSPECTION_TIME: Duration = Duration::from_millis(750);

#[derive(Debug, Clone)]
pub struct EmbeddedFinding {
    pub path: String,
    pub depth: u8,
    pub verdict: DetectionVerdict,
    pub risk_score: u8,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub automatic_quarantine_eligible: bool,
    pub execution_block_eligible: bool,
}

impl EmbeddedFinding {
    pub fn verdict_rank(&self) -> u8 {
        match self.verdict {
            DetectionVerdict::Clean => 0,
            DetectionVerdict::Error => 1,
            DetectionVerdict::Suspicious => 2,
            DetectionVerdict::Malicious => 3,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContainerInspection {
    pub scanned_entries: usize,
    pub expanded_bytes: u64,
    pub encrypted_entries: usize,
    pub macro_projects: usize,
    pub executable_attachments: usize,
    pub external_relationships: usize,
    pub rejected_paths: usize,
    /// Structure typical of a decompression bomb: an extreme compression ratio, or archives
    /// nested past `MAX_ARCHIVE_DEPTH`. Raises suspicion on its own.
    pub limit_triggered: bool,
    /// Not everything was inspected: too many entries, an entry or the total too large, or the
    /// time budget spent. Ordinary large archives end up here, so it raises no suspicion; the
    /// result is reported as incomplete instead and is not cached as a clean verdict.
    pub incomplete: bool,
    pub malformed: bool,
    pub findings: Vec<EmbeddedFinding>,
}

impl ContainerInspection {
    pub fn structural_risk_score(&self) -> u8 {
        if self.limit_triggered {
            60
        } else if self.macro_projects > 0
            && (self.executable_attachments > 0 || self.external_relationships > 0)
        {
            65
        } else if self.rejected_paths > 0 || self.malformed {
            35
        } else {
            0
        }
    }
}

struct InspectionState {
    started: Instant,
    report: ContainerInspection,
}

pub fn inspect_zip<F>(bytes: &[u8], mut scan_leaf: F) -> ContainerInspection
where
    F: FnMut(&[u8]) -> DetectionReport,
{
    let mut state = InspectionState {
        started: Instant::now(),
        report: ContainerInspection::default(),
    };
    walk_zip(bytes, "", 1, &mut state, &mut scan_leaf);
    state.report
}

pub fn inspect_ole<F>(bytes: &[u8], mut scan_leaf: F) -> ContainerInspection
where
    F: FnMut(&[u8]) -> DetectionReport,
{
    inspect_ole_with_limit(bytes, &mut scan_leaf, MAX_TOTAL_EXPANDED_BYTES)
}

fn inspect_ole_with_limit<F>(
    bytes: &[u8],
    scan_leaf: &mut F,
    max_expanded_bytes: u64,
) -> ContainerInspection
where
    F: FnMut(&[u8]) -> DetectionReport,
{
    let mut report = ContainerInspection::default();
    let mut compound = match cfb::OpenOptions::new()
        .strict()
        .max_buffer_size(1024 * 1024)
        .open_with(Cursor::new(bytes))
    {
        Ok(compound) => compound,
        Err(_) => {
            report.malformed = true;
            return report;
        }
    };
    let entries = compound
        .walk()
        .filter(|entry| entry.is_stream())
        .map(|entry| {
            (
                entry.path().to_path_buf(),
                entry.len(),
                entry.name().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        report.incomplete = true;
    }
    let started = Instant::now();
    for (path, size, name) in entries.into_iter().take(MAX_ARCHIVE_ENTRIES) {
        if started.elapsed() > MAX_INSPECTION_TIME {
            report.incomplete = true;
            break;
        }
        report.scanned_entries += 1;
        if size > MAX_ENTRY_BYTES || report.expanded_bytes.saturating_add(size) > max_expanded_bytes
        {
            report.incomplete = true;
            continue;
        }
        let path_text = path.to_string_lossy().replace('\\', "/");
        if path_text.chars().count() > MAX_ENTRY_NAME_CHARS {
            report.rejected_paths += 1;
            continue;
        }
        let lower = path_text.to_ascii_lowercase();
        let is_vba = lower.contains("/vba/")
            || name.eq_ignore_ascii_case("_VBA_PROJECT")
            || name.eq_ignore_ascii_case("dir");
        if is_vba {
            report.macro_projects += 1;
        }
        let mut stream = match compound.open_stream(&path) {
            Ok(stream) => stream,
            Err(_) => {
                report.malformed = true;
                continue;
            }
        };
        let mut contents = Vec::with_capacity(size as usize);
        if stream
            .by_ref()
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut contents)
            .is_err()
            || contents.len() as u64 != size
        {
            report.malformed = true;
            continue;
        }
        report.expanded_bytes = report.expanded_bytes.saturating_add(contents.len() as u64);
        record_finding(&path_text, 1, scan_leaf(&contents), &mut report);

        if is_vba {
            for offset in contents
                .iter()
                .enumerate()
                .filter_map(|(offset, byte)| (*byte == 1).then_some(offset))
                .take(16)
            {
                if let Ok(decompressed) = vba::decompress(&contents[offset..], 4 * 1024 * 1024) {
                    if decompressed
                        .windows(13)
                        .any(|value| value == b"Attribute VB_")
                    {
                        record_finding(
                            &format!("{path_text}#decompressed-vba"),
                            1,
                            scan_leaf(&decompressed),
                            &mut report,
                        );
                        break;
                    }
                }
            }
        }
    }
    report
}

pub fn inspect_gzip<F>(bytes: &[u8], mut scan_leaf: F) -> ContainerInspection
where
    F: FnMut(&[u8]) -> DetectionReport,
{
    let mut report = ContainerInspection::default();
    // Every member: a gzip file may be several concatenated, and decoding only the first left
    // whatever followed it unscanned.
    let mut decoder = MultiGzDecoder::new(bytes);
    let mut contents = Vec::new();
    match decoder
        .by_ref()
        .take(MAX_ENTRY_BYTES + 1)
        .read_to_end(&mut contents)
    {
        Ok(_) if contents.len() as u64 <= MAX_ENTRY_BYTES => {}
        Ok(_) => {
            report.incomplete = true;
            return report;
        }
        Err(_) => {
            report.malformed = true;
            return report;
        }
    }
    if contents.len() > 1024 * 1024
        && (bytes.is_empty()
            || contents.len() as u64 / (bytes.len() as u64).max(1) > MAX_COMPRESSION_RATIO)
    {
        report.limit_triggered = true;
        return report;
    }
    report.scanned_entries = 1;
    report.expanded_bytes = contents.len() as u64;
    record_finding("gzip:/payload", 1, scan_leaf(&contents), &mut report);
    report
}

fn record_finding(
    path: &str,
    depth: u8,
    report: DetectionReport,
    inspection: &mut ContainerInspection,
) {
    if report.verdict != DetectionVerdict::Clean && inspection.findings.len() < MAX_FINDINGS {
        inspection.findings.push(EmbeddedFinding {
            path: path.to_owned(),
            depth,
            verdict: report.verdict,
            risk_score: report.risk_score,
            threat_name: report.threat_name,
            sha256: report.sha256,
            automatic_quarantine_eligible: report.automatic_quarantine_eligible,
            execution_block_eligible: report.execution_block_eligible,
        });
    }
}

fn walk_zip<F>(
    bytes: &[u8],
    prefix: &str,
    depth: u8,
    state: &mut InspectionState,
    scan_leaf: &mut F,
) where
    F: FnMut(&[u8]) -> DetectionReport,
{
    if depth > MAX_ARCHIVE_DEPTH {
        state.report.limit_triggered = true;
        return;
    }
    if state.started.elapsed() > MAX_INSPECTION_TIME {
        state.report.incomplete = true;
        return;
    }
    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(_) => {
            state.report.malformed = true;
            return;
        }
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES.saturating_sub(state.report.scanned_entries) {
        state.report.incomplete = true;
    }

    for index in 0..archive.len() {
        if state.report.scanned_entries >= MAX_ARCHIVE_ENTRIES
            || state.started.elapsed() > MAX_INSPECTION_TIME
        {
            state.report.incomplete = true;
            break;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => {
                state.report.malformed = true;
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        state.report.scanned_entries += 1;
        let Some(enclosed) = entry.enclosed_name() else {
            state.report.rejected_paths += 1;
            continue;
        };
        let entry_name = enclosed.to_string_lossy().replace('\\', "/");
        if entry_name.chars().count() > MAX_ENTRY_NAME_CHARS {
            state.report.rejected_paths += 1;
            continue;
        }
        let full_name = if prefix.is_empty() {
            entry_name.clone()
        } else {
            format!("{prefix}!/{entry_name}")
        };
        observe_office_structure(&entry_name, &mut state.report);

        if entry.encrypted() {
            state.report.encrypted_entries += 1;
            continue;
        }
        let expanded = entry.size();
        let compressed = entry.compressed_size();
        let ratio_exceeded = expanded > 1024 * 1024
            && (compressed == 0 || expanded / compressed.max(1) > MAX_COMPRESSION_RATIO);
        if ratio_exceeded {
            state.report.limit_triggered = true;
            continue;
        }
        if expanded > MAX_ENTRY_BYTES
            || state.report.expanded_bytes.saturating_add(expanded) > MAX_TOTAL_EXPANDED_BYTES
        {
            state.report.incomplete = true;
            continue;
        }

        let mut contents = Vec::with_capacity(expanded.min(MAX_ENTRY_BYTES) as usize);
        if entry
            .by_ref()
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut contents)
            .is_err()
            || contents.len() as u64 != expanded
        {
            state.report.malformed = true;
            continue;
        }
        state.report.expanded_bytes = state
            .report
            .expanded_bytes
            .saturating_add(contents.len() as u64);
        if entry_name.ends_with(".rels") {
            state.report.external_relationships = state
                .report
                .external_relationships
                .saturating_add(count_external_relationships(&contents));
        }

        record_finding(&full_name, depth, scan_leaf(&contents), &mut state.report);
        if contents.starts_with(b"PK\x03\x04") {
            if depth == MAX_ARCHIVE_DEPTH {
                state.report.limit_triggered = true;
            } else {
                walk_zip(&contents, &full_name, depth + 1, state, scan_leaf);
            }
        } else if contents.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
            let remaining = MAX_TOTAL_EXPANDED_BYTES.saturating_sub(state.report.expanded_bytes);
            if remaining == 0 {
                state.report.incomplete = true;
            } else {
                let nested = inspect_ole_with_limit(&contents, scan_leaf, remaining);
                merge_nested_inspection(&full_name, depth, nested, &mut state.report);
            }
        }
    }
}

fn merge_nested_inspection(
    prefix: &str,
    parent_depth: u8,
    nested: ContainerInspection,
    report: &mut ContainerInspection,
) {
    report.scanned_entries = report
        .scanned_entries
        .saturating_add(nested.scanned_entries);
    report.expanded_bytes = report.expanded_bytes.saturating_add(nested.expanded_bytes);
    report.encrypted_entries = report
        .encrypted_entries
        .saturating_add(nested.encrypted_entries);
    report.macro_projects = report.macro_projects.saturating_add(nested.macro_projects);
    report.executable_attachments = report
        .executable_attachments
        .saturating_add(nested.executable_attachments);
    report.external_relationships = report
        .external_relationships
        .saturating_add(nested.external_relationships);
    report.rejected_paths = report.rejected_paths.saturating_add(nested.rejected_paths);
    report.limit_triggered |= nested.limit_triggered;
    report.incomplete |= nested.incomplete;
    report.malformed |= nested.malformed;
    for mut finding in nested.findings {
        if report.findings.len() >= MAX_FINDINGS {
            break;
        }
        finding.path = format!("{prefix}!/{}", finding.path);
        finding.depth = parent_depth.saturating_add(finding.depth);
        report.findings.push(finding);
    }
}

fn observe_office_structure(name: &str, report: &mut ContainerInspection) {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with("vbaproject.bin") || lower.contains("/macros/") {
        report.macro_projects += 1;
    }
    if lower.contains("/embeddings/")
        || lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".scr")
        || lower.ends_with(".js")
        || lower.ends_with(".vbs")
        || lower.ends_with(".ps1")
    {
        report.executable_attachments += 1;
    }
}

fn count_external_relationships(bytes: &[u8]) -> usize {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    lower.matches("targetmode=\"external\"").count()
        + lower.matches("targetmode='external'").count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::DetectionEngine;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut output);
            for (name, contents) in entries {
                writer
                    .start_file(*name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(contents).unwrap();
            }
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    #[test]
    fn exact_signature_is_found_inside_zip() {
        let zip = make_zip(&[("invoice.txt", crate::self_test::PAYLOAD)]);
        let engine = DetectionEngine::builtin().unwrap();
        let result = inspect_zip(&zip, |bytes| engine.scan_leaf_bytes(bytes));
        assert_eq!(result.scanned_entries, 1);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].automatic_quarantine_eligible);

        let outer = engine.scan_bytes(&zip);
        assert_eq!(outer.verdict, DetectionVerdict::Malicious);
        assert!(outer.should_quarantine());
        assert_eq!(
            outer
                .container_inspection
                .as_ref()
                .map(|inspection| inspection.findings.len()),
            Some(1)
        );
    }

    #[test]
    fn a_large_ordinary_archive_is_incomplete_not_suspicious() {
        let names: Vec<String> = (0..MAX_ARCHIVE_ENTRIES + 10)
            .map(|index| format!("src/file{index}.txt"))
            .collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), b"plain text".as_slice()))
            .collect();
        let zip = make_zip(&entries);
        let engine = DetectionEngine::builtin().unwrap();

        let result = inspect_zip(&zip, |bytes| engine.scan_leaf_bytes(bytes));
        assert!(result.incomplete);
        assert!(!result.limit_triggered);
        assert_eq!(result.structural_risk_score(), 0);

        let report = engine.scan_bytes(&zip);
        assert_eq!(report.verdict, DetectionVerdict::Clean);
        assert_eq!(
            report.analysis_completeness,
            crate::engine::AnalysisCompleteness::ResourceLimitReached
        );
    }

    #[test]
    fn traversal_names_are_rejected_without_extraction() {
        let zip = make_zip(&[("../../outside.exe", b"not executable")]);
        let engine = DetectionEngine::builtin().unwrap();
        let result = inspect_zip(&zip, |bytes| engine.scan_leaf_bytes(bytes));
        assert_eq!(result.rejected_paths, 1);
        assert_eq!(result.expanded_bytes, 0);
    }

    #[test]
    fn office_macro_and_external_relationship_are_correlated() {
        let rels = br#"<Relationship TargetMode="External" Target="https://example.invalid"/>"#;
        let zip = make_zip(&[
            ("word/vbaProject.bin", b"macro"),
            ("word/_rels/a.rels", rels),
        ]);
        let engine = DetectionEngine::builtin().unwrap();
        let result = inspect_zip(&zip, |bytes| engine.scan_leaf_bytes(bytes));
        assert_eq!(result.macro_projects, 1);
        assert_eq!(result.external_relationships, 1);
        assert_eq!(result.structural_risk_score(), 65);
    }

    #[test]
    fn office_zip_recurses_into_bounded_ole_streams() {
        let mut compound = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        compound.create_storage("/VBA").unwrap();
        compound
            .create_stream("/VBA/Module1")
            .unwrap()
            .write_all(crate::self_test::PAYLOAD)
            .unwrap();
        let ole = compound.into_inner().into_inner();
        let zip = make_zip(&[("word/vbaProject.bin", &ole)]);
        let engine = DetectionEngine::builtin().unwrap();
        let result = inspect_zip(&zip, |bytes| engine.scan_leaf_bytes(bytes));
        assert!(result.macro_projects >= 2);
        assert!(
            result.findings.iter().any(|finding| {
                finding.path.contains("vbaProject.bin")
                    && finding.path.contains("VBA/Module1")
                    && finding.automatic_quarantine_eligible
            }),
            "nested findings were {:?}",
            result.findings
        );
        assert!(engine.scan_bytes(&zip).should_quarantine());
    }

    #[test]
    fn every_member_of_a_concatenated_gzip_is_scanned() {
        let member = |contents: &[u8]| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(contents).unwrap();
            encoder.finish().unwrap()
        };
        let mut gzip = member(b"an innocent first member\n");
        gzip.extend(member(crate::self_test::PAYLOAD));
        let engine = DetectionEngine::builtin().unwrap();
        let mut scanned = Vec::new();
        inspect_gzip(&gzip, |bytes| {
            scanned = bytes.to_vec();
            engine.scan_leaf_bytes(bytes)
        });
        assert!(scanned.starts_with(b"an innocent first member\n"));
        assert!(scanned.ends_with(crate::self_test::PAYLOAD));
    }

    #[test]
    fn exact_signature_is_found_inside_gzip() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(crate::self_test::PAYLOAD).unwrap();
        let gzip = encoder.finish().unwrap();
        let engine = DetectionEngine::builtin().unwrap();
        let result = inspect_gzip(&gzip, |bytes| engine.scan_leaf_bytes(bytes));
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].automatic_quarantine_eligible);
        assert!(engine.scan_bytes(&gzip).should_quarantine());
    }
}
