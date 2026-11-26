use crate::atomic_file;
use crate::config::Settings;
use crate::ipc::IpcClient;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const ELEVATED_ACTION_ARGUMENT: &str = "--elevated-action";
const MAX_SETTINGS_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum QuarantineAdminAction {
    Restore,
    Delete,
}

pub fn request_save_settings(settings: &Settings) -> Result<(), String> {
    let bytes = serde_json::to_vec(settings)
        .map_err(|error| format!("could not encode the settings request: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_SETTINGS_REQUEST_BYTES {
        return Err("the settings request exceeds its size limit".to_owned());
    }
    let directory = elevation_request_directory();
    fs::create_dir_all(&directory)
        .map_err(|error| format!("could not prepare the UAC request directory: {error}"))?;
    let path = directory.join(format!("settings-{}.json", Uuid::new_v4()));
    atomic_file::write(&path, &bytes)
        .map_err(|error| format!("could not stage the settings request: {error}"))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let arguments = [
        OsString::from(ELEVATED_ACTION_ARGUMENT),
        OsString::from("save-settings"),
        path.as_os_str().to_owned(),
        OsString::from(digest),
    ];
    if let Err(error) = launch_elevated(&arguments) {
        let _ = fs::remove_file(&path);
        return Err(format!("could not request administrator approval: {error}"));
    }
    Ok(())
}

pub fn request_quarantine_action(action: QuarantineAdminAction, id: Uuid) -> Result<(), String> {
    let action = match action {
        QuarantineAdminAction::Restore => "restore-quarantine",
        QuarantineAdminAction::Delete => "delete-quarantine",
    };
    launch_elevated(&[
        OsString::from(ELEVATED_ACTION_ARGUMENT),
        OsString::from(action),
        OsString::from(id.to_string()),
    ])
    .map_err(|error| format!("could not request administrator approval: {error}"))
}

pub fn request_clear_activity() -> Result<(), String> {
    launch_elevated(&[
        OsString::from(ELEVATED_ACTION_ARGUMENT),
        OsString::from("clear-activity"),
    ])
    .map_err(|error| format!("could not request administrator approval: {error}"))
}

pub fn elevated_action_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(ELEVATED_ACTION_ARGUMENT)) {
        return None;
    }
    let Some(action) = arguments.next() else {
        return Some(2);
    };
    let result = match action.to_str() {
        Some("save-settings") => {
            let Some(path) = arguments.next() else {
                return Some(2);
            };
            let Some(expected_digest) = arguments.next() else {
                return Some(2);
            };
            if arguments.next().is_some() {
                return Some(2);
            }
            apply_settings_request(Path::new(&path), &expected_digest.to_string_lossy())
        }
        Some("restore-quarantine") | Some("delete-quarantine") => {
            let Some(id) = arguments.next() else {
                return Some(2);
            };
            if arguments.next().is_some() {
                return Some(2);
            }
            let id = match Uuid::parse_str(&id.to_string_lossy()) {
                Ok(id) => id,
                Err(_) => return Some(2),
            };
            let client = IpcClient;
            let restore = action == OsStr::new("restore-quarantine");
            let record = client
                .list_quarantine()
                .ok()
                .and_then(|records| records.into_iter().find(|record| record.id == id));
            let what = record
                .map(|record| format!("{} ({})", record.threat_name, record.original_path))
                .unwrap_or_else(|| format!("quarantine item {id}"));
            let line = if restore {
                format!("put {what} back where it was. it was quarantined as malware")
            } else {
                format!("permanently delete {what} from quarantine")
            };
            if !confirm(&[line]) {
                return Some(1);
            }
            if restore {
                client.restore_quarantine(id).map(|_| ())
            } else {
                client.delete_quarantine(id).map(|_| ())
            }
            .map_err(|error| error.to_string())
        }
        Some("clear-activity") => {
            if arguments.next().is_some() {
                return Some(2);
            }
            if !confirm(&["clear the whole activity history".to_owned()]) {
                return Some(1);
            }
            IpcClient
                .clear_activity()
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        _ => return Some(2),
    };
    Some(if result.is_ok() { 0 } else { 1 })
}

fn apply_settings_request(path: &Path, expected_digest: &str) -> Result<(), String> {
    validate_settings_request_path(path)?;
    if expected_digest.len() != 64 || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("the settings request digest is invalid".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect the settings request: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SETTINGS_REQUEST_BYTES as u64
    {
        return Err("the settings request is not a bounded regular file".to_owned());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("could not read the settings request: {error}"))?;
    let actual_digest = hex::encode(Sha256::digest(&bytes));
    if !actual_digest.eq_ignore_ascii_case(expected_digest) {
        return Err("the settings request changed after UAC approval was requested".to_owned());
    }
    let settings: Settings = serde_json::from_slice(&bytes)
        .map_err(|error| format!("the settings request is invalid: {error}"))?;
    let current = IpcClient
        .get_settings()
        .map_err(|error| format!("the current settings could not be read: {error}"))?;
    let changes = settings.describe_changes_from(&current);
    if !changes.is_empty() && !confirm(&changes) {
        return Err("the change was declined".to_owned());
    }
    IpcClient
        .save_settings(settings)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Asks, in this elevated process's own window, before an administrator action takes effect.
///
/// The administrator prompt cannot say what is being approved, and any program can raise one for
/// this executable with arguments of its choosing: it would look exactly like the routine "pause"
/// prompt. This window says what will happen, and a program without administrator rights cannot
/// click it for the person, since Windows keeps lower-integrity input out of elevated windows.
/// "No" is the default button.
fn confirm(lines: &[String]) -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(window: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    const MB_YESNO: u32 = 0x0004;
    const MB_ICONWARNING: u32 = 0x0030;
    const MB_DEFBUTTON2: u32 = 0x0100;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const MB_TOPMOST: u32 = 0x0004_0000;
    const IDYES: i32 = 6;
    let text = format!(
        "blackshard was given administrator approval to:\n\n{}\n\ngo ahead? if you did not ask for this, choose no.",
        lines
            .iter()
            .map(|line| format!("  - {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let wide =
        |value: &str| -> Vec<u16> { value.encode_utf16().chain(std::iter::once(0)).collect() };
    let text = wide(&text);
    let caption = wide("blackshard: confirm");
    unsafe {
        MessageBoxW(
            0,
            text.as_ptr(),
            caption.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
        ) == IDYES
    }
}

fn validate_settings_request_path(path: &Path) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "the settings request file name is invalid".to_owned())?;
    let id = file_name
        .strip_prefix("settings-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or_else(|| "the settings request file name is invalid".to_owned())?;
    Uuid::parse_str(id).map_err(|_| "the settings request identifier is invalid".to_owned())?;
    let parent = path
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str);
    let grandparent = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str);
    if parent != Some("elevation") || grandparent != Some("blackshard") || !path.is_absolute() {
        return Err("the settings request is outside the expected staging layout".to_owned());
    }
    Ok(())
}

fn elevation_request_directory() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("blackshard")
        .join("elevation")
}

#[cfg(windows)]
fn launch_elevated(arguments: &[OsString]) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            window: isize,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_command: i32,
        ) -> isize;
    }

    let executable = std::env::current_exe()?;
    let executable = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let operation = "runas".encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let parameters = encode_windows_arguments(arguments);
    let result = unsafe {
        ShellExecuteW(
            0,
            operation.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            0,
        )
    };
    if result <= 32 {
        Err(io::Error::from_raw_os_error(result as i32))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn launch_elevated(_arguments: &[OsString]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UAC elevation is available only on Windows",
    ))
}

#[cfg(windows)]
fn encode_windows_arguments(arguments: &[OsString]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut command_line = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            command_line.push(b' ' as u16);
        }
        command_line.push(b'"' as u16);
        let encoded = argument.encode_wide().collect::<Vec<_>>();
        let mut backslashes = 0usize;
        for unit in encoded {
            if unit == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if unit == b'"' as u16 {
                command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                command_line.push(unit);
            } else {
                command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                command_line.push(unit);
            }
            backslashes = 0;
        }
        command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        command_line.push(b'"' as u16);
    }
    command_line.push(0);
    command_line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_settings_paths_are_narrowly_named() {
        let valid = PathBuf::from(r"C:\Users\Test\AppData\Local\blackshard\elevation")
            .join(format!("settings-{}.json", Uuid::new_v4()));
        assert!(validate_settings_request_path(&valid).is_ok());
        assert!(validate_settings_request_path(Path::new(r"C:\Windows\system.ini")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_argument_encoding_quotes_spaces_and_trailing_slashes() {
        use std::os::windows::ffi::OsStringExt;
        let encoded = encode_windows_arguments(&[
            OsString::from("--mode"),
            OsString::from(r"C:\Path With Space\"),
        ]);
        let text = OsString::from_wide(&encoded[..encoded.len() - 1])
            .to_string_lossy()
            .into_owned();
        assert_eq!(text, r#""--mode" "C:\Path With Space\\""#);
    }
}
