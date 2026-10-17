use crate::config::Settings;
use crate::detection::{DetectionEngine, DetectionReport, DetectionVerdict};
use crate::history::{EventHistory, EventKind, SecurityEvent};
use crate::notifications::notify_detection;
use crate::quarantine::{IsolationState, QuarantineRecord, QuarantineStore};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

const MAX_VISIBLE_FINDINGS: usize = 250;

#[derive(Debug, Clone)]
pub enum ScanKind {
    Quick,
    Full,
    Custom(Vec<PathBuf>),
}

impl ScanKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Quick => "Quick scan",
            Self::Full => "Full scan",
            Self::Custom(_) => "Custom scan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Enumerating,
    Scanning,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub path: PathBuf,
    pub report: DetectionReport,
    pub quarantine: Option<QuarantineRecord>,
    pub action_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub id: Uuid,
    pub kind: ScanKind,
    pub phase: ScanPhase,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub current_path: Option<PathBuf>,
    pub discovered_files: u64,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub clean_files: u64,
    pub suspicious_files: u64,
    pub malicious_files: u64,
    pub quarantined_files: u64,
    pub errors: u64,
    pub findings: VecDeque<ScanFinding>,
    pub elapsed: Duration,
    pub failure: Option<String>,
}

impl ScanProgress {
    fn new(kind: ScanKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            phase: ScanPhase::Enumerating,
            started_at: Utc::now(),
            finished_at: None,
            current_path: None,
            discovered_files: 0,
            scanned_files: 0,
            scanned_bytes: 0,
            clean_files: 0,
            suspicious_files: 0,
            malicious_files: 0,
            quarantined_files: 0,
            errors: 0,
            findings: VecDeque::new(),
            elapsed: Duration::ZERO,
            failure: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.phase,
            ScanPhase::Completed | ScanPhase::Cancelled | ScanPhase::Failed
        )
    }
}

pub struct ScanJob {
    progress: Arc<Mutex<ScanProgress>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ScanJob {
    pub fn start(
        kind: ScanKind,
        engine: Arc<DetectionEngine>,
        quarantine: Arc<QuarantineStore>,
        history: Arc<EventHistory>,
        settings: Settings,
    ) -> Self {
        let progress = Arc::new(Mutex::new(ScanProgress::new(kind.clone())));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_progress = Arc::clone(&progress);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::spawn(move || {
            run_scan(
                kind,
                engine,
                quarantine,
                history,
                settings,
                worker_progress,
                worker_cancelled,
            )
        });

        Self {
            progress,
            cancelled,
            worker: Some(worker),
        }
    }

    pub fn snapshot(&self) -> ScanProgress {
        // A panic elsewhere while holding the lock leaves progress that is still worth showing.
        lock_progress(&self.progress).clone()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut progress) = self.progress.lock() {
            if !progress.is_finished() {
                progress.phase = ScanPhase::Cancelling;
            }
        }
    }

    pub fn join_if_finished(&mut self) {
        if self.snapshot().is_finished() {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    /// Blocks until the scan worker has finished and returns its final progress.
    ///
    /// Callers that need a settled result should prefer this over polling `snapshot`, which makes
    /// the outcome depend on how quickly the machine happens to get through the queue.
    pub fn join(&mut self) -> ScanProgress {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.snapshot()
    }
}

impl Drop for ScanJob {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

fn run_scan(
    kind: ScanKind,
    engine: Arc<DetectionEngine>,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Settings,
    progress: Arc<Mutex<ScanProgress>>,
    cancelled: Arc<AtomicBool>,
) {
    let started = Instant::now();
    let mut start_event = SecurityEvent::new(EventKind::ScanStarted, kind.display_name());
    start_event.details = Some(format!("scan_id={}", lock_progress(&progress).id));
    let _ = history.append(&start_event);

    let roots = match scan_roots(&kind, &settings) {
        Ok(roots) if !roots.is_empty() => roots,
        Ok(_) => {
            finish_failed(&progress, started, "no accessible scan roots were found");
            return;
        }
        Err(error) => {
            finish_failed(&progress, started, error);
            return;
        }
    };

    let worker_count = if settings.low_resource_mode {
        settings.worker_count.min(2)
    } else {
        settings.worker_count
    }
    .max(1);
    let (path_sender, path_receiver) = mpsc::sync_channel::<PathBuf>(worker_count * 8);
    let shared_receiver = Arc::new(Mutex::new(path_receiver));

    let enumeration_progress = Arc::clone(&progress);
    let enumeration_cancelled = Arc::clone(&cancelled);
    let enumeration_settings = settings.clone();
    let enumeration_quarantine_root = quarantine.root().to_path_buf();
    let enumerator = thread::spawn(move || {
        enumerate_files(
            roots,
            &enumeration_settings,
            &enumeration_quarantine_root,
            &path_sender,
            &enumeration_progress,
            &enumeration_cancelled,
        )
    });

    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let receiver = Arc::clone(&shared_receiver);
        let engine = Arc::clone(&engine);
        let quarantine = Arc::clone(&quarantine);
        let history = Arc::clone(&history);
        let settings = settings.clone();
        let progress = Arc::clone(&progress);
        let cancelled = Arc::clone(&cancelled);
        workers.push(thread::spawn(move || {
            scan_worker(
                receiver, engine, quarantine, history, settings, progress, cancelled,
            )
        }));
    }

    let enumeration_result = enumerator.join();
    for worker in workers {
        let _ = worker.join();
    }

    let was_cancelled = cancelled.load(Ordering::Acquire);
    let mut current = lock_progress(&progress);
    current.current_path = None;
    current.elapsed = started.elapsed();
    current.finished_at = Some(Utc::now());
    if enumeration_result.is_err() {
        current.phase = ScanPhase::Failed;
        current.failure = Some("file enumeration worker panicked".to_owned());
    } else if was_cancelled {
        current.phase = ScanPhase::Cancelled;
    } else {
        current.phase = ScanPhase::Completed;
    }

    let mut completed_event = SecurityEvent::new(
        EventKind::ScanCompleted,
        format!(
            "{}: {} files, {} malicious, {} suspicious",
            current.kind.display_name(),
            current.scanned_files,
            current.malicious_files,
            current.suspicious_files
        ),
    );
    completed_event.details = Some(format!(
        "scan_id={}; cancelled={}; errors={}; quarantined={}",
        current.id, was_cancelled, current.errors, current.quarantined_files
    ));
    drop(current);
    let _ = history.append(&completed_event);
}

fn enumerate_files(
    roots: Vec<PathBuf>,
    settings: &Settings,
    quarantine_root: &Path,
    sender: &mpsc::SyncSender<PathBuf>,
    progress: &Arc<Mutex<ScanProgress>>,
    cancelled: &AtomicBool,
) {
    for root in roots {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        if root.is_file() {
            enqueue_file(root, settings, quarantine_root, sender, progress, cancelled);
            continue;
        }

        let walker = WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| should_descend(entry, settings, quarantine_root));
        for entry in walker {
            if cancelled.load(Ordering::Acquire) {
                break;
            }
            match entry {
                Ok(entry) if entry.file_type().is_file() => enqueue_file(
                    entry.into_path(),
                    settings,
                    quarantine_root,
                    sender,
                    progress,
                    cancelled,
                ),
                Ok(_) => {}
                Err(_) => lock_progress(progress).errors += 1,
            }
        }
    }
}

fn enqueue_file(
    path: PathBuf,
    settings: &Settings,
    quarantine_root: &Path,
    sender: &mpsc::SyncSender<PathBuf>,
    progress: &Arc<Mutex<ScanProgress>>,
    cancelled: &AtomicBool,
) {
    if cancelled.load(Ordering::Acquire)
        || settings.is_excluded(&path)
        || path.starts_with(quarantine_root)
        || (!settings.scan_archives && is_archive_container(&path))
    {
        return;
    }
    let maximum = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.len() <= maximum => {
            let mut pending = path;
            loop {
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                match sender.try_send(pending) {
                    Ok(()) => {
                        lock_progress(progress).discovered_files += 1;
                        break;
                    }
                    Err(mpsc::TrySendError::Full(path)) => {
                        pending = path;
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => return,
                }
            }
        }
        Ok(_) => {}
        Err(_) => lock_progress(progress).errors += 1,
    }
}

fn should_descend(entry: &DirEntry, settings: &Settings, quarantine_root: &Path) -> bool {
    let path = entry.path();
    !settings.is_excluded(path) && !path.starts_with(quarantine_root)
}

#[allow(clippy::too_many_arguments)]
fn scan_worker(
    receiver: Arc<Mutex<mpsc::Receiver<PathBuf>>>,
    engine: Arc<DetectionEngine>,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Settings,
    progress: Arc<Mutex<ScanProgress>>,
    cancelled: Arc<AtomicBool>,
) {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return;
        }
        let path = {
            let receiver = match receiver.lock() {
                Ok(receiver) => receiver,
                Err(_) => return,
            };
            match receiver.recv() {
                Ok(path) => path,
                Err(_) => return,
            }
        };

        {
            let mut current = lock_progress(&progress);
            current.phase = ScanPhase::Scanning;
            current.current_path = Some(path.clone());
        }
        let report = engine.scan_path(&path);
        let mut quarantine_record = None;
        let mut action_error = None;

        if report.should_quarantine() && settings.automatic_quarantine {
            let threat_name = report.threat_name.as_deref().unwrap_or("Known.Malware");
            let quarantine_result = match report.sha256.as_deref() {
                Some(hash) => quarantine.quarantine_verified(
                    &path,
                    threat_name,
                    report.risk_score,
                    hash,
                    report.file_size,
                    None,
                ),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the complete file was not hashed; automatic quarantine was withheld",
                )),
            };
            match quarantine_result {
                Ok(record) => {
                    let isolated = record.state == IsolationState::Isolated;
                    if isolated {
                        lock_progress(&progress).quarantined_files += 1;
                    } else {
                        action_error = Some(
                            "a neutralized copy was created, but the original remains".to_owned(),
                        );
                    }
                    if settings.notify_on_detection {
                        let _ = notify_detection(threat_name, &path, isolated);
                    }
                    let mut event = SecurityEvent::new(
                        if isolated {
                            EventKind::Quarantined
                        } else {
                            EventKind::QuarantineFailed
                        },
                        if isolated {
                            "Threat moved to quarantine"
                        } else {
                            "Threat detected; original could not be removed"
                        },
                    );
                    event.path = Some(path.clone());
                    event.threat_name = Some(threat_name.to_owned());
                    event.risk_score = Some(report.risk_score);
                    event.details = record.cleanup_summary();
                    let _ = history.append(&event);
                    quarantine_record = Some(record);
                }
                Err(error) => {
                    action_error = Some(error.to_string());
                    let mut event = SecurityEvent::new(
                        EventKind::QuarantineFailed,
                        "Threat detected; quarantine failed",
                    );
                    event.path = Some(path.clone());
                    event.threat_name = report.threat_name.clone();
                    event.risk_score = Some(report.risk_score);
                    event.details = action_error.clone();
                    let _ = history.append(&event);
                    if settings.notify_on_detection {
                        let _ = notify_detection(
                            report.threat_name.as_deref().unwrap_or("Known.Malware"),
                            &path,
                            false,
                        );
                    }
                }
            }
        }

        let mut current = lock_progress(&progress);
        current.scanned_files += 1;
        current.scanned_bytes = current.scanned_bytes.saturating_add(report.file_size);
        match report.verdict {
            DetectionVerdict::Clean => current.clean_files += 1,
            DetectionVerdict::Suspicious => current.suspicious_files += 1,
            DetectionVerdict::Malicious => current.malicious_files += 1,
            DetectionVerdict::Error => current.errors += 1,
        }
        if report.verdict != DetectionVerdict::Clean {
            if current.findings.len() == MAX_VISIBLE_FINDINGS {
                current.findings.pop_front();
            }
            current.findings.push_back(ScanFinding {
                path,
                report,
                quarantine: quarantine_record,
                action_error,
            });
        }
        if settings.low_resource_mode {
            drop(current);
            thread::sleep(Duration::from_millis(2));
        }
    }
}

fn scan_roots(kind: &ScanKind, settings: &Settings) -> Result<Vec<PathBuf>, String> {
    let roots = match kind {
        ScanKind::Quick => quick_scan_roots(),
        ScanKind::Full => full_scan_roots(settings.scan_network_drives),
        ScanKind::Custom(paths) => paths.clone(),
    };
    // Canonical roots give every path found under them its final form, which is what
    // `Settings::is_excluded` compares against.
    let mut roots = roots
        .into_iter()
        .filter_map(|path| fs::canonicalize(path).ok())
        .map(strip_verbatim_prefix)
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// `\\?\C:\x` back to `C:\x`, so canonical roots still compare equal to ordinary paths such as
/// the quarantine root. UNC and device paths keep their prefix.
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    match path.to_string_lossy().strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

fn is_archive_container(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "7z" | "cab" | "gz" | "iso" | "rar" | "tar" | "tgz" | "xz" | "zip"
            )
        })
}

fn quick_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        roots.push(profile.join("Desktop"));
        roots.push(profile.join("Downloads"));
        roots.push(profile.join("AppData").join("Local").join("Temp"));
        roots.push(
            profile
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }
    if let Some(program_data) = std::env::var_os("PROGRAMDATA").map(PathBuf::from) {
        roots.push(
            program_data
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("StartUp"),
        );
    }
    if let Some(temp) = std::env::var_os("TEMP").map(PathBuf::from) {
        roots.push(temp);
    }
    roots
}

#[cfg(windows)]
fn full_scan_roots(include_network_drives: bool) -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStrExt;

    const DRIVE_NO_ROOT_DIR: u32 = 1;
    const DRIVE_REMOTE: u32 = 4;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(root_path_name: *const u16) -> u32;
    }
    let mask = unsafe { GetLogicalDrives() };
    (0..26)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| PathBuf::from(format!("{}:\\", (b'A' + bit as u8) as char)))
        .filter(|root| {
            let mut wide = root.as_os_str().encode_wide().collect::<Vec<_>>();
            wide.push(0);
            let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
            drive_type != DRIVE_NO_ROOT_DIR
                && (include_network_drives || drive_type != DRIVE_REMOTE)
        })
        .collect()
}

#[cfg(not(windows))]
fn full_scan_roots(_include_network_drives: bool) -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

fn finish_failed(progress: &Arc<Mutex<ScanProgress>>, started: Instant, error: impl Into<String>) {
    let mut current = lock_progress(progress);
    current.phase = ScanPhase::Failed;
    current.failure = Some(error.into());
    current.elapsed = started.elapsed();
    current.finished_at = Some(Utc::now());
}

fn lock_progress(progress: &Arc<Mutex<ScanProgress>>) -> std::sync::MutexGuard<'_, ScanProgress> {
    progress
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::EventHistory;

    #[test]
    fn custom_scan_detects_and_quarantines_inert_blackshard_test_object() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("targets");
        fs::create_dir_all(&target).unwrap();
        let test_path = target.join("blackshard-inert-test.com");
        fs::write(&test_path, crate::self_test::PAYLOAD).unwrap();
        fs::write(target.join("clean.txt"), b"ordinary text").unwrap();

        let engine = Arc::new(DetectionEngine::builtin().unwrap());
        let quarantine = Arc::new(QuarantineStore::new(temporary.path().join("vault")));
        let history = Arc::new(EventHistory::new(temporary.path().join("history.jsonl")));
        let mut job = ScanJob::start(
            ScanKind::Custom(vec![target]),
            engine,
            quarantine,
            history,
            Settings::default(),
        );

        let progress = job.join();
        assert_eq!(progress.phase, ScanPhase::Completed);
        assert_eq!(progress.scanned_files, 2);
        assert_eq!(progress.malicious_files, 1);
        assert_eq!(progress.quarantined_files, 1);
        assert!(!test_path.exists());
    }

    #[test]
    fn scan_can_be_cancelled() {
        let temporary = tempfile::tempdir().unwrap();
        for index in 0..100 {
            fs::write(temporary.path().join(format!("{index}.txt")), b"clean").unwrap();
        }
        let engine = Arc::new(DetectionEngine::builtin().unwrap());
        let quarantine = Arc::new(QuarantineStore::new(temporary.path().join("vault")));
        let history = Arc::new(EventHistory::new(temporary.path().join("history.jsonl")));
        let mut job = ScanJob::start(
            ScanKind::Custom(vec![temporary.path().to_path_buf()]),
            engine,
            quarantine,
            history,
            Settings::default(),
        );
        job.cancel();
        assert!(matches!(job.join().phase, ScanPhase::Cancelled));
    }

    #[test]
    fn archive_setting_skips_only_archive_containers() {
        assert!(is_archive_container(Path::new("sample.ZIP")));
        assert!(is_archive_container(Path::new("backup.tar")));
        assert!(!is_archive_container(Path::new("program.exe")));
        assert!(!is_archive_container(Path::new("archive.zip.exe")));
    }
}
