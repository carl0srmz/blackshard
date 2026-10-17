use crate::atomic_file;
use crate::history::{EventKind, SecurityEvent};
use crate::ipc::BLOCK_ACCEPTED_TOKEN;
use crate::notifications::{notify_blocked, notify_detection};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The most events the service returns per request (`MAX_ACTIVITY_RESULTS`).
const EVENTS_PER_POLL: usize = 200;
const CURSOR_SCHEMA_VERSION: u32 = 1;
/// One toast per file in this window: a blocked launch is followed by its quarantine.
const SAME_PATH_QUIET_SECONDS: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationCursor {
    schema_version: u32,
    last_seen: DateTime<Utc>,
}

pub fn run() -> Result<(), String> {
    let _single_instance = SingleInstance::acquire()?;
    let cursor_path = cursor_path();
    let mut last_seen = load_cursor(&cursor_path).unwrap_or_else(|_| Utc::now());
    save_cursor(&cursor_path, last_seen)
        .map_err(|error| format!("could not initialize the notification cursor: {error}"))?;
    let mut last_toast_by_path = HashMap::<PathBuf, DateTime<Utc>>::new();

    loop {
        // Through the service rather than the files: history and settings live in the private
        // State folder, and this runs as whoever is signed in. A service that is not running
        // has nothing new to report; the next poll picks up where this one left off.
        if let Ok((mut events, enabled)) = fetch_from_service() {
            events.sort_by_key(|event| event.timestamp);
            for event in events.into_iter() {
                if event.timestamp <= last_seen {
                    continue;
                }
                last_seen = last_seen.max(event.timestamp);
                let (Some(toast), Some(path), Some(threat_name), true) = (
                    toast_for(&event),
                    event.path.as_deref(),
                    event.threat_name.as_deref(),
                    enabled,
                ) else {
                    continue;
                };
                if last_toast_by_path.get(path).is_some_and(|shown| {
                    (event.timestamp - *shown).num_seconds() < SAME_PATH_QUIET_SECONDS
                }) {
                    continue;
                }
                last_toast_by_path.insert(path.to_path_buf(), event.timestamp);
                let _ = match toast {
                    Toast::Removed => notify_detection(threat_name, path, true),
                    Toast::NotRemoved => notify_detection(threat_name, path, false),
                    Toast::Blocked => notify_blocked(threat_name, path),
                };
            }
            last_toast_by_path
                .retain(|_, shown| (last_seen - *shown).num_seconds() < SAME_PATH_QUIET_SECONDS);
            let _ = save_cursor(&cursor_path, last_seen);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Recent events, as the service trims them for a standard user (file names, no details beyond
/// whether a launch was blocked), and whether detection notifications are on.
#[cfg(windows)]
fn fetch_from_service() -> Result<(Vec<SecurityEvent>, bool), crate::ipc::RpcFailure> {
    let client = crate::ipc::IpcClient;
    let events = client.recent_activity(EVENTS_PER_POLL)?;
    let enabled = client.get_settings()?.notify_on_detection;
    Ok((events, enabled))
}

#[cfg(not(windows))]
fn fetch_from_service() -> Result<(Vec<SecurityEvent>, bool), String> {
    Err("the protection service is only reachable on Windows".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Toast {
    Removed,
    NotRemoved,
    Blocked,
}

fn toast_for(event: &SecurityEvent) -> Option<Toast> {
    match event.kind {
        EventKind::Quarantined => Some(Toast::Removed),
        EventKind::QuarantineFailed => Some(Toast::NotRemoved),
        // Real-time detections record whether the driver accepted the block; a suspicious file
        // that was only observed stays quiet, or every Explorer thumbnail would raise a toast.
        EventKind::Detection
            if event
                .details
                .as_deref()
                .is_some_and(|details| details.contains(BLOCK_ACCEPTED_TOKEN)) =>
        {
            Some(Toast::Blocked)
        }
        _ => None,
    }
}

fn cursor_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("blackshard")
        .join("notification-cursor.json")
}

fn load_cursor(path: &std::path::Path) -> io::Result<DateTime<Utc>> {
    let bytes = fs::read(path)?;
    if bytes.len() > 4 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "notification cursor exceeds its size limit",
        ));
    }
    let cursor: NotificationCursor = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if cursor.schema_version != CURSOR_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "notification cursor schema is unsupported",
        ));
    }
    Ok(cursor.last_seen)
}

fn save_cursor(path: &std::path::Path, last_seen: DateTime<Utc>) -> io::Result<()> {
    let bytes = serde_json::to_vec(&NotificationCursor {
        schema_version: CURSOR_SCHEMA_VERSION,
        last_seen,
    })
    .map_err(io::Error::other)?;
    atomic_file::write(path, &bytes)
}

#[cfg(windows)]
struct SingleInstance(isize);

#[cfg(windows)]
impl SingleInstance {
    fn acquire() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateMutexW(
                mutex_attributes: *const std::ffi::c_void,
                initial_owner: i32,
                name: *const u16,
            ) -> isize;
        }

        let name = "Local\\blackshard-notification-agent\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle == 0 {
            return Err(format!(
                "could not create the notification-agent mutex: {}",
                io::Error::last_os_error()
            ));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err("the notification agent is already running".to_owned());
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(not(windows))]
struct SingleInstance;

#[cfg(not(windows))]
impl SingleInstance {
    fn acquire() -> Result<Self, String> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_blocks_and_removals_raise_toasts() {
        let mut event =
            SecurityEvent::new(EventKind::Detection, "Real-time suspicious file observed");
        event.details = Some("block_reply_accepted=false; pid=4".to_owned());
        assert_eq!(toast_for(&event), None);
        event.details = Some("block_reply_accepted=true; pid=4".to_owned());
        assert_eq!(toast_for(&event), Some(Toast::Blocked));
        // What the service hands a standard user's session after trimming the details.
        event.details = Some(BLOCK_ACCEPTED_TOKEN.to_owned());
        assert_eq!(toast_for(&event), Some(Toast::Blocked));
        event.kind = EventKind::Quarantined;
        assert_eq!(toast_for(&event), Some(Toast::Removed));
        event.kind = EventKind::ScanCompleted;
        assert_eq!(toast_for(&event), None);
    }

    #[test]
    fn cursor_round_trip_is_bounded_and_versioned() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cursor.json");
        let now = Utc::now();
        save_cursor(&path, now).unwrap();
        assert_eq!(load_cursor(&path).unwrap(), now);
        fs::write(&path, vec![b'x'; 4097]).unwrap();
        assert_eq!(
            load_cursor(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
