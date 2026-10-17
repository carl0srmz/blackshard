use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const DEFAULT_HISTORY_LIMIT: usize = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProtectionStarted,
    ProtectionStopped,
    ScanStarted,
    ScanCompleted,
    Detection,
    Quarantined,
    QuarantineFailed,
    Restored,
    UpdateInstalled,
    UpdateFailed,
    Error,
    /// The history was cleared; the first entry afterwards, naming who cleared it.
    ActivityCleared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub summary: String,
    pub path: Option<PathBuf>,
    pub threat_name: Option<String>,
    pub risk_score: Option<u8>,
    pub details: Option<String>,
}

impl SecurityEvent {
    pub fn new(kind: EventKind, summary: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            summary: summary.into(),
            path: None,
            threat_name: None,
            risk_score: None,
            details: None,
        }
    }
}

#[derive(Debug)]
pub struct EventHistory {
    path: PathBuf,
    writer_lock: Mutex<()>,
}

impl EventHistory {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writer_lock: Mutex::new(()),
        }
    }

    /// In the private `State` folder: it holds full paths from every profile on the machine.
    /// Clients read it through the service, which trims what a standard user sees.
    pub fn default_for_machine() -> Self {
        Self::new(crate::paths::state_dir().join("history.jsonl"))
    }

    pub fn append(&self, event: &SecurityEvent) -> io::Result<()> {
        let _guard = self
            .writer_lock
            .lock()
            .map_err(|_| io::Error::other("history writer lock was poisoned"))?;
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "history path has no parent")
        })?;
        fs::create_dir_all(parent)?;
        self.rotate_if_needed()?;

        let mut bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "security event exceeds its serialization limit",
            ));
        }
        bytes.push(b'\n');
        let mut output = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        output.write_all(&bytes)?;

        if matches!(
            event.kind,
            EventKind::Detection | EventKind::Quarantined | EventKind::QuarantineFailed
        ) {
            output.sync_data()?;
        }
        Ok(())
    }

    pub fn recent(&self, limit: usize) -> io::Result<Vec<SecurityEvent>> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "security history is not a regular, non-symlink file",
            ));
        }
        if metadata.len() > MAX_LOG_BYTES + MAX_EVENT_BYTES as u64 + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "security history exceeds its size limit",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(&self.path)?
            .take(MAX_LOG_BYTES + MAX_EVENT_BYTES as u64 + 2)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LOG_BYTES + MAX_EVENT_BYTES as u64 + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "security history grew beyond its size limit while being read",
            ));
        }

        let keep = limit.clamp(1, DEFAULT_HISTORY_LIMIT);
        let mut events = VecDeque::with_capacity(keep);
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() || line.len() > MAX_EVENT_BYTES {
                continue;
            }
            if let Ok(event) = serde_json::from_slice(line) {
                events.push_back(event);
                if events.len() > keep {
                    events.pop_front();
                }
            }
        }
        Ok(events.into_iter().rev().collect())
    }

    pub fn clear(&self) -> io::Result<()> {
        let _guard = self
            .writer_lock
            .lock()
            .map_err(|_| io::Error::other("history writer lock was poisoned"))?;
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn rotate_if_needed(&self) -> io::Result<()> {
        let size = fs::metadata(&self.path).map(|item| item.len()).unwrap_or(0);
        if size < MAX_LOG_BYTES {
            return Ok(());
        }

        let rotated = self.path.with_extension("jsonl.1");
        if rotated.exists() {
            fs::remove_file(&rotated)?;
        }
        fs::rename(&self.path, rotated)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_round_trip_keeps_newest_first() {
        let temporary = tempfile::tempdir().unwrap();
        let history = EventHistory::new(temporary.path().join("history.jsonl"));
        history
            .append(&SecurityEvent::new(EventKind::ScanStarted, "first"))
            .unwrap();
        history
            .append(&SecurityEvent::new(EventKind::ScanCompleted, "second"))
            .unwrap();

        let events = history.recent(10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "second");
        assert_eq!(events[1].summary, "first");
    }

    #[test]
    fn malformed_lines_do_not_hide_valid_events() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("history.jsonl");
        let history = EventHistory::new(&path);
        history
            .append(&SecurityEvent::new(EventKind::Error, "valid"))
            .unwrap();
        let mut output = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(output, "not-json").unwrap();

        let events = history.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "valid");
    }
}
