//! Logging for the service, which has no console: everything sent to stderr is discarded.
//!
//! Lines go to `State\logs\service.log`, readable by administrators only, since log lines name
//! files from every profile. The file is capped at `MAX_LOG_BYTES`; the previous one is kept as
//! `service.log.1`, so at most twice that is ever on disk.

use chrono::Utc;
use log::{LevelFilter, Log, Metadata, Record};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

pub struct FileLogger {
    path: PathBuf,
    level: LevelFilter,
    state: Mutex<Option<(File, u64)>>,
}

impl FileLogger {
    pub fn new(path: impl Into<PathBuf>, level: LevelFilter) -> Self {
        Self {
            path: path.into(),
            level,
            state: Mutex::new(None),
        }
    }

    fn write_line(&self, line: &str) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .as_ref()
            .is_some_and(|(_, written)| *written + line.len() as u64 > MAX_LOG_BYTES)
        {
            *state = None;
            let _ = fs::rename(&self.path, rotated(&self.path));
        }
        if state.is_none() {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            let written = file.metadata()?.len();
            *state = Some((file, written));
        }
        let (file, written) = state.as_mut().expect("opened above");
        file.write_all(line.as_bytes())?;
        *written += line.len() as u64;
        Ok(())
    }
}

fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} {}: {}\n",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            record.level(),
            record.target(),
            record.args()
        );
        // Nowhere left to report a failure to write the log.
        let _ = self.write_line(&line);
    }

    fn flush(&self) {
        if let Some((file, _)) = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            let _ = file.flush();
        }
    }
}

/// The service's log file.
pub fn default_path() -> PathBuf {
    crate::paths::state_dir().join("logs").join("service.log")
}

/// Sends `log` output to `path`, and panics there too, for the life of the process.
pub fn init(path: PathBuf) -> Result<(), log::SetLoggerError> {
    let logger: &'static FileLogger = Box::leak(Box::new(FileLogger::new(path, LevelFilter::Info)));
    log::set_logger(logger)?;
    log::set_max_level(LevelFilter::Info);

    // A panic on a worker thread used to vanish with stderr; the thread just stopped.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        log::error!(
            "panic on thread {}: {info}\n{}",
            thread.name().unwrap_or("<unnamed>"),
            std::backtrace::Backtrace::force_capture()
        );
        log::logger().flush();
        previous(info);
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_rotates_once_it_reaches_its_cap() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("logs").join("service.log");
        let logger = FileLogger::new(&path, LevelFilter::Info);
        let line = "x".repeat(1023) + "\n";
        for _ in 0..(MAX_LOG_BYTES / 1024) {
            logger.write_line(&line).unwrap();
        }
        assert!(!rotated(&path).exists());
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_LOG_BYTES);

        logger.write_line("next\n").unwrap();
        assert_eq!(fs::metadata(rotated(&path)).unwrap().len(), MAX_LOG_BYTES);
        assert_eq!(fs::read_to_string(&path).unwrap(), "next\n");
    }

    #[test]
    fn levels_below_the_filter_are_dropped() {
        let logger = FileLogger::new("unused.log", LevelFilter::Info);
        assert!(logger.enabled(&Metadata::builder().level(log::Level::Warn).build()));
        assert!(!logger.enabled(&Metadata::builder().level(log::Level::Debug).build()));
    }
}
