use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::Instant;

const WINDOW_MILLIS: u64 = 10_000;
const ALERT_COOLDOWN_MILLIS: u64 = 10_000;
const UNTRUSTED_THRESHOLD: usize = 24;
const UNKNOWN_THRESHOLD: usize = 32;
const TRUSTED_THRESHOLD: usize = 80;
const MAX_TRACKED_PROCESSES: usize = 256;
const MAX_EVENTS_PER_PROCESS: usize = 128;
const UNTRUSTED_ENCRYPTED_THRESHOLD: usize = 3;
const UNKNOWN_ENCRYPTED_THRESHOLD: usize = 5;
const HIGH_ENTROPY_WRITE: u8 = 1;
const RENAMED_OR_DELETED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTrust {
    Trusted,
    Unknown,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropyObservation {
    NotMeasured,
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileAction {
    Read,
    Write { entropy: EntropyObservation },
    Rename,
    Delete,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BehaviorDecision {
    pub protected_path: bool,
    pub distinct_files: usize,
    pub alert: bool,
    pub block: bool,
}

#[derive(Default)]
struct ProcessActivity {
    events: VecDeque<(u64, u64)>,
    /// Per-file `HIGH_ENTROPY_WRITE | RENAMED_OR_DELETED` flags, for the files in `events`.
    actions: HashMap<u64, u8>,
    last_seen_millis: u64,
    last_alert_millis: Option<u64>,
}

pub struct RansomwareMonitor {
    started: Instant,
    processes: HashMap<(u32, u64), ProcessActivity>,
}

struct BehaviorObservation<'a> {
    process_id: u32,
    process_start_key: u64,
    path: &'a Path,
    trust: ProcessTrust,
    block_mode: bool,
    now_millis: u64,
    action: Option<FileAction>,
}

impl Default for RansomwareMonitor {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            processes: HashMap::new(),
        }
    }
}

impl RansomwareMonitor {
    pub fn observe(
        &mut self,
        process_id: u32,
        process_start_key: u64,
        path: &Path,
        trust: ProcessTrust,
        block_mode: bool,
        action: Option<FileAction>,
    ) -> BehaviorDecision {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.observe_at(BehaviorObservation {
            process_id,
            process_start_key,
            path,
            trust,
            block_mode,
            now_millis: elapsed,
            action,
        })
    }

    fn observe_at(&mut self, observation: BehaviorObservation<'_>) -> BehaviorDecision {
        let BehaviorObservation {
            process_id,
            process_start_key,
            path,
            trust,
            block_mode,
            now_millis,
            action,
        } = observation;

        if !is_protected_document(path) || process_id == 0 || process_start_key == 0 {
            return BehaviorDecision::default();
        }
        self.evict_stale(now_millis);
        if self.processes.len() >= MAX_TRACKED_PROCESSES
            && !self
                .processes
                .contains_key(&(process_id, process_start_key))
        {
            if let Some(oldest) = self
                .processes
                .iter()
                .min_by_key(|(_, activity)| activity.last_seen_millis)
                .map(|(key, _)| *key)
            {
                self.processes.remove(&oldest);
            }
        }

        let activity = self
            .processes
            .entry((process_id, process_start_key))
            .or_default();
        activity.last_seen_millis = now_millis;
        while activity
            .events
            .front()
            .is_some_and(|(timestamp, _)| now_millis.saturating_sub(*timestamp) > WINDOW_MILLIS)
        {
            if let Some((_, expired)) = activity.events.pop_front() {
                activity.actions.remove(&expired);
            }
        }
        let fingerprint = path_fingerprint(path);
        let flag = match action {
            Some(FileAction::Write {
                entropy: EntropyObservation::High,
            }) => HIGH_ENTROPY_WRITE,
            Some(FileAction::Rename) => RENAMED_OR_DELETED,
            _ => 0,
        };
        *activity.actions.entry(fingerprint).or_default() |= flag;

        if !activity
            .events
            .iter()
            .any(|(_, existing)| *existing == fingerprint)
        {
            activity.events.push_back((now_millis, fingerprint));
            while activity.events.len() > MAX_EVENTS_PER_PROCESS {
                if let Some((_, evicted)) = activity.events.pop_front() {
                    activity.actions.remove(&evicted);
                }
            }
        }
        let distinct_files = activity
            .events
            .iter()
            .map(|(_, fingerprint)| *fingerprint)
            .collect::<HashSet<_>>()
            .len();
        // A file overwritten with high-entropy data and then renamed or deleted is what in-place
        // encryption looks like, but so is saving a .png or .docx and renaming it. A handful of
        // such files from an unsigned program is the signal; one file, or a signed program, is not.
        let encrypted_files = activity
            .actions
            .values()
            .filter(|flags| **flags == HIGH_ENTROPY_WRITE | RENAMED_OR_DELETED)
            .count();
        let (threshold, encrypted_threshold) = match trust {
            ProcessTrust::Trusted => (TRUSTED_THRESHOLD, usize::MAX),
            ProcessTrust::Unknown => (UNKNOWN_THRESHOLD, UNKNOWN_ENCRYPTED_THRESHOLD),
            ProcessTrust::Untrusted => (UNTRUSTED_THRESHOLD, UNTRUSTED_ENCRYPTED_THRESHOLD),
        };
        let threshold_reached =
            distinct_files >= threshold || encrypted_files >= encrypted_threshold;
        let alert = threshold_reached
            && activity
                .last_alert_millis
                .is_none_or(|last| now_millis.saturating_sub(last) >= ALERT_COOLDOWN_MILLIS);
        if alert {
            activity.last_alert_millis = Some(now_millis);
        }
        BehaviorDecision {
            protected_path: true,
            distinct_files,
            alert,
            block: threshold_reached && block_mode,
        }
    }

    fn evict_stale(&mut self, now_millis: u64) {
        self.processes.retain(|_, activity| {
            now_millis.saturating_sub(activity.last_seen_millis) <= WINDOW_MILLIS * 6
        });
    }
}

fn is_protected_document(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let protected_folder = [
        "\\desktop\\",
        "\\documents\\",
        "\\pictures\\",
        "\\music\\",
        "\\videos\\",
        "\\favorites\\",
        "\\onedrive\\",
        "\\onedrive - ",
    ]
    .iter()
    .any(|component| normalized.contains(component));
    if !normalized.contains("\\users\\") || !protected_folder {
        return false;
    }
    let extension = normalized.rsplit_once('.').map(|(_, extension)| extension);
    matches!(
        extension,
        Some(
            "doc"
                | "docx"
                | "docm"
                | "xls"
                | "xlsx"
                | "xlsm"
                | "ppt"
                | "pptx"
                | "pptm"
                | "pdf"
                | "txt"
                | "rtf"
                | "csv"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "bmp"
                | "svg"
                | "mp3"
                | "wav"
                | "mp4"
                | "mov"
                | "avi"
                | "zip"
                | "7z"
                | "rar"
                | "sql"
                | "db"
                | "sqlite"
                | "psd"
                | "ai"
        )
    )
}

fn path_fingerprint(path: &Path) -> u64 {
    let normalized = path.to_string_lossy().to_ascii_lowercase();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(index: usize) -> std::path::PathBuf {
        format!(r"\Device\HarddiskVolume3\Users\Alice\Documents\file-{index}.docx").into()
    }

    #[test]
    fn distinct_mass_modification_alerts_and_can_block() {
        let mut monitor = RansomwareMonitor::default();
        let mut decision = BehaviorDecision::default();
        for index in 0..UNTRUSTED_THRESHOLD {
            decision = monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 9_999,
                path: &document(index),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index as u64,
                action: None,
            });
        }
        assert!(decision.alert);
        assert!(decision.block);
        assert_eq!(decision.distinct_files, UNTRUSTED_THRESHOLD);
    }

    #[test]
    fn repeated_writes_to_one_file_do_not_trigger() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..100 {
            let decision = monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 9_999,
                path: &document(1),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index,
                action: None,
            });
            assert!(!decision.block);
        }
    }

    #[test]
    fn stable_process_key_prevents_pid_reuse_correlation() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..UNTRUSTED_THRESHOLD - 1 {
            monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 1,
                path: &document(index),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index as u64,
                action: None,
            });
        }
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 2,
            path: &document(999),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 100,
            action: None,
        });
        assert_eq!(decision.distinct_files, 1);
        assert!(!decision.block);
    }

    #[test]
    fn non_user_or_non_document_paths_are_ignored() {
        let mut monitor = RansomwareMonitor::default();
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 1,
            process_start_key: 2,
            path: Path::new(r"C:\Windows\Temp\sample.bin"),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 0,
            action: None,
        });
        assert!(!decision.protected_path);
    }

    #[test]
    fn unmeasured_entropy_does_not_count_as_high_entropy() {
        let mut monitor = RansomwareMonitor::default();
        let path = document(1);
        let write = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: &path,
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 1,
            action: Some(FileAction::Write {
                entropy: EntropyObservation::NotMeasured,
            }),
        });
        let rename = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: &path,
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 2,
            action: Some(FileAction::Rename),
        });
        assert!(!write.block);
        assert!(!rename.block);
    }

    #[test]
    fn public_canary_like_filename_is_not_trusted_as_a_secret_canary() {
        let mut monitor = RansomwareMonitor::default();
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: Path::new(r"C:\Users\Alice\Documents\canary-budget.docx"),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 1,
            action: Some(FileAction::Write {
                entropy: EntropyObservation::NotMeasured,
            }),
        });
        assert!(!decision.block);
        assert!(!decision.alert);
    }

    fn encrypt(
        monitor: &mut RansomwareMonitor,
        trust: ProcessTrust,
        index: usize,
    ) -> BehaviorDecision {
        let path = document(index);
        let observe = |monitor: &mut RansomwareMonitor, action| {
            monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 9_999,
                path: &path,
                trust,
                block_mode: true,
                now_millis: index as u64 * 10,
                action: Some(action),
            })
        };
        observe(
            monitor,
            FileAction::Write {
                entropy: EntropyObservation::High,
            },
        );
        observe(monitor, FileAction::Rename)
    }

    #[test]
    fn one_high_entropy_save_and_rename_is_not_ransomware() {
        let mut monitor = RansomwareMonitor::default();
        let decision = encrypt(&mut monitor, ProcessTrust::Untrusted, 1);
        assert!(!decision.alert && !decision.block);
    }

    #[test]
    fn a_few_encrypted_files_from_an_unsigned_writer_block_early() {
        let mut monitor = RansomwareMonitor::default();
        let decisions = (0..UNTRUSTED_ENCRYPTED_THRESHOLD)
            .map(|index| encrypt(&mut monitor, ProcessTrust::Untrusted, index))
            .collect::<Vec<_>>();
        assert!(decisions[..UNTRUSTED_ENCRYPTED_THRESHOLD - 1]
            .iter()
            .all(|decision| !decision.block));
        assert!(decisions.last().unwrap().alert && decisions.last().unwrap().block);
    }

    #[test]
    fn signed_writers_never_trip_the_encryption_pattern() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..20 {
            assert!(!encrypt(&mut monitor, ProcessTrust::Trusted, index).block);
        }
    }
}
