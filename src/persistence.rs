//! Startup entries that would relaunch a file blackshard removed.
//!
//! Quarantining a program leaves whatever it registered to start with Windows pointing at a file
//! that is gone. That is harmless until something puts a file back at that path, and it is clutter
//! either way, so the Run and RunOnce entries that launch it are removed with it: machine-wide,
//! in the 32-bit view, and in every user hive that is loaded.
//!
//! Scheduled tasks and Win32 services that launch the file are removed too. Startup-folder
//! shortcuts and WMI subscriptions are the next places to clean. Paths written with 8.3 short
//! names are not matched.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, RRF_RT_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// A scheduled task or service of this kind is a program started by Windows: a Win32 service that
/// runs in its own process or shares one. Kernel drivers (types 1 and 2) are left alone.
const SERVICE_WIN32_OWN_OR_SHARE: u32 = 0x10 | 0x20;
const MAX_TASK_FILES: usize = 5_000;
const MAX_TASK_FILE_BYTES: u64 = 256 * 1024;

/// Removes the scheduled tasks and Win32 services that launch `target`, and describes each one.
///
/// Nothing is removed for a file inside the Windows folder: Windows itself registers tasks and
/// services there, and a quarantined system file is a different problem from a dropped program.
pub fn remove_tasks_and_services_for(target: &Path) -> Vec<String> {
    let target = comparable(&target.to_string_lossy());
    if target.is_empty() || is_under_windows_folder(&target) {
        return Vec::new();
    }
    let mut removed = remove_tasks(&target);
    removed.extend(remove_services(&target));
    removed
}

fn windows_folder() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

fn is_under_windows_folder(target: &str) -> bool {
    let root = comparable(&windows_folder().to_string_lossy());
    target.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
}

fn remove_tasks(target: &str) -> Vec<String> {
    let tasks_folder = windows_folder().join(r"System32\Tasks");
    let mut found = Vec::new();
    collect_task_files(&tasks_folder, &tasks_folder, 0, &mut found);

    let schtasks = windows_folder().join(r"System32\schtasks.exe");
    let mut removed = Vec::new();
    for (name, definition) in found {
        let launches_target = crate::remediation::task_command_lines(&definition)
            .iter()
            .any(|line| launches(line, None, target));
        if !launches_target {
            continue;
        }
        let deleted = Command::new(&schtasks)
            .args(["/Delete", "/TN", &name, "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .is_ok_and(|status| status.success());
        if deleted {
            log::warn!("Removed scheduled task {name}");
            removed.push(format!("scheduled task: {name}"));
        }
    }
    removed
}

/// Every task definition under `folder` as (task name such as `\Vendor\Task`, file contents).
fn collect_task_files(
    root: &Path,
    folder: &Path,
    depth: usize,
    found: &mut Vec<(String, Vec<u8>)>,
) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        if found.len() >= MAX_TASK_FILES {
            return;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        // Links are skipped: a task definition is a plain file, and following a junction could
        // lead the walk out of the Tasks folder.
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_task_files(root, &path, depth + 1, found);
        } else if kind.is_file()
            && entry
                .metadata()
                .is_ok_and(|metadata| metadata.len() <= MAX_TASK_FILE_BYTES)
        {
            if let (Ok(relative), Ok(bytes)) = (path.strip_prefix(root), std::fs::read(&path)) {
                found.push((format!(r"\{}", relative.display()), bytes));
            }
        }
    }
}

fn remove_services(target: &str) -> Vec<String> {
    const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
    let sc = windows_folder().join(r"System32\sc.exe");
    let mut removed = Vec::new();
    for service in subkeys(HKEY_LOCAL_MACHINE, SERVICES) {
        let key = format!(r"{SERVICES}\{service}");
        let service_type = registry_dword(HKEY_LOCAL_MACHINE, &key, "Type").unwrap_or(0);
        if service_type & SERVICE_WIN32_OWN_OR_SHARE == 0 {
            continue;
        }
        let Some(image_path) = registry_string(HKEY_LOCAL_MACHINE, &key, "ImagePath") else {
            continue;
        };
        if !launches(&image_path, None, target) {
            continue;
        }
        let run = |action: &str| {
            Command::new(&sc)
                .args([action, &service])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .is_ok_and(|status| status.success())
        };
        // Stopped first, so the file is no longer held open by the service's process.
        let _ = run("stop");
        if run("delete") {
            log::warn!("Removed service {service}: {image_path}");
            removed.push(format!("service: {service}"));
        }
    }
    removed
}

fn registry_string(root: HKEY, path: &str, name: &str) -> Option<String> {
    let path = wide(path);
    let name = wide(name);
    let mut buffer = vec![0u16; 4096];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    (status == 0).then(|| utf16_bytes(bytemuck_u16(&buffer, size)))
}

fn registry_dword(root: HKEY, path: &str, name: &str) -> Option<u32> {
    let path = wide(path);
    let name = wide(name);
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_DWORD,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0).then_some(value)
}

const RUN_KEYS: [&str; 4] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

/// Removes every Run and RunOnce entry whose command launches `target`, and describes each one
/// removed, as `HKU\<sid>\...\Run: <name>`.
pub fn remove_autostarts_for(target: &Path) -> Vec<String> {
    let target = comparable(&target.to_string_lossy());
    if target.is_empty() {
        return Vec::new();
    }
    let mut removed = Vec::new();
    for key in RUN_KEYS {
        removed.extend(clean_key(HKEY_LOCAL_MACHINE, "HKLM", key, None, &target));
    }
    for sid in subkeys(HKEY_USERS, "") {
        // `<sid>_Classes` holds file associations, not the user's Run keys.
        if sid.ends_with("_Classes") {
            continue;
        }
        let profile = profile_path(&sid);
        for key in RUN_KEYS {
            let path = format!(r"{sid}\{key}");
            removed.extend(clean_key(
                HKEY_USERS,
                "HKU",
                &path,
                profile.as_deref(),
                &target,
            ));
        }
    }
    removed
}

fn clean_key(
    root: HKEY,
    root_name: &str,
    path: &str,
    profile: Option<&str>,
    target: &str,
) -> Vec<String> {
    let Some(key) = open(root, path, KEY_QUERY_VALUE | KEY_SET_VALUE) else {
        return Vec::new();
    };
    // Collected first: deleting while enumerating shifts the indices still to be visited.
    let mut matches = Vec::new();
    for index in 0.. {
        let mut name = vec![0u16; 16_384];
        let mut name_length = name.len() as u32;
        let mut kind = 0u32;
        let mut data = vec![0u8; 64 * 1024];
        let mut data_length = data.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_length,
            )
        };
        // ERROR_NO_MORE_ITEMS ends the walk; a value too large for the buffer is not a command.
        if status == 259 {
            break;
        }
        if status != 0 || !matches!(kind, REG_SZ | REG_EXPAND_SZ) {
            continue;
        }
        let command = utf16_bytes(&data[..data_length as usize]);
        if launches(&command, profile, target) {
            name.truncate(name_length as usize);
            matches.push((name, command));
        }
    }
    let mut removed = Vec::new();
    for (mut name, command) in matches {
        let display = String::from_utf16_lossy(&name);
        name.push(0);
        if unsafe { RegDeleteValueW(key, name.as_ptr()) } == 0 {
            log::warn!("Removed startup entry {root_name}\\{path}: {display} = {command}");
            removed.push(format!("{root_name}\\{path}: {display}"));
        }
    }
    unsafe { RegCloseKey(key) };
    removed
}

/// Whether a startup command, with its environment variables expanded for the profile it belongs
/// to, runs `target`.
fn launches(command: &str, profile: Option<&str>, target: &str) -> bool {
    comparable(&expand(command, profile)).contains(target)
}

/// Expands `%VARIABLE%`s. The per-user ones come from the hive's own profile: this runs as SYSTEM,
/// whose own %APPDATA% would point into the system profile.
fn expand(command: &str, profile: Option<&str>) -> String {
    let mut expanded = String::with_capacity(command.len());
    let mut rest = command;
    while let Some(start) = rest.find('%') {
        let Some(length) = rest[start + 1..].find('%') else {
            break;
        };
        let name = &rest[start + 1..start + 1 + length];
        let per_user = |suffix: &str| profile.map(|profile| format!("{profile}{suffix}"));
        let value = match name.to_ascii_uppercase().as_str() {
            "USERPROFILE" => per_user(""),
            "APPDATA" => per_user(r"\AppData\Roaming"),
            "LOCALAPPDATA" => per_user(r"\AppData\Local"),
            "TEMP" | "TMP" => per_user(r"\AppData\Local\Temp"),
            _ => None,
        }
        .or_else(|| std::env::var(name).ok());
        expanded.push_str(&rest[..start]);
        match value {
            Some(value) => expanded.push_str(&value),
            None => expanded.push_str(&rest[start..start + length + 2]),
        }
        rest = &rest[start + length + 2..];
    }
    expanded.push_str(rest);
    expanded
}

/// Lower case, forward slashes turned back, and no `\\?\` prefix.
fn comparable(path: &str) -> String {
    let lower = path.replace('/', "\\").to_lowercase();
    lower.strip_prefix(r"\\?\").unwrap_or(&lower).to_owned()
}

fn profile_path(sid: &str) -> Option<String> {
    let key = wide(&format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
    ));
    let value = wide("ProfileImagePath");
    let mut buffer = vec![0u16; 1024];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    (status == 0).then(|| utf16_bytes(bytemuck_u16(&buffer, size)))
}

fn subkeys(root: HKEY, path: &str) -> Vec<String> {
    let Some(key) = open(root, path, KEY_ENUMERATE_SUB_KEYS) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for index in 0.. {
        let mut name = vec![0u16; 256];
        let mut length = name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            break;
        }
        names.push(String::from_utf16_lossy(&name[..length as usize]));
    }
    unsafe { RegCloseKey(key) };
    names
}

fn open(root: HKEY, path: &str, access: u32) -> Option<HKEY> {
    let path = wide(path);
    let mut key: HKEY = 0;
    (unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut key) } == 0)
        .then_some(key)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn bytemuck_u16(buffer: &[u16], size_bytes: u32) -> &[u8] {
    let bytes = (size_bytes as usize).min(buffer.len() * 2);
    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), bytes) }
}

/// Registry string data: UTF-16LE, usually but not always NUL-terminated.
fn utf16_bytes(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_user_variables_expand_into_that_users_profile() {
        let target = comparable(r"C:\Users\alice\AppData\Roaming\evil\evil.exe");
        let profile = Some(r"C:\Users\alice");
        assert!(launches(
            r#""%APPDATA%\evil\evil.exe" --hidden"#,
            profile,
            &target
        ));
        assert!(launches(
            r"c:/users/ALICE/appdata/roaming/evil/evil.exe",
            None,
            &target
        ));
        assert!(!launches(
            r"%APPDATA%\evil\evil.exe",
            Some(r"C:\Users\bob"),
            &target
        ));
        assert!(!launches(
            r"C:\Program Files\Tool\tool.exe",
            profile,
            &target
        ));
        assert_eq!(
            expand("%NOT_A_VARIABLE_42%\\x", None),
            "%NOT_A_VARIABLE_42%\\x"
        );
    }

    #[test]
    fn nothing_registered_by_windows_itself_is_touched() {
        let system = comparable(&windows_folder().join(r"System32\cmd.exe").to_string_lossy());
        assert!(is_under_windows_folder(&system));
        assert!(!is_under_windows_folder(&comparable(
            r"C:\Users\alice\AppData\Roaming\evil.exe"
        )));
        // A folder that merely starts with the same letters is not the Windows folder.
        let lookalike = format!(
            "{}old\\x.exe",
            comparable(&windows_folder().to_string_lossy())
        );
        assert!(!is_under_windows_folder(&lookalike));
        assert!(
            remove_tasks_and_services_for(&windows_folder().join(r"System32\cmd.exe")).is_empty()
        );
    }

    #[test]
    fn an_unrelated_file_matches_no_task_or_service() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("no-such-task-launches-this.exe");
        assert!(remove_tasks_and_services_for(&target).is_empty());
    }

    #[test]
    fn a_run_entry_for_a_removed_file_is_deleted_and_others_are_kept() {
        use windows_sys::Win32::System::Registry::{RegSetValueExW, HKEY_CURRENT_USER};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("autostart-sample.exe");
        let name = format!("blackshard-test-{}", uuid::Uuid::new_v4());
        let unrelated = format!("{name}-unrelated");
        let key = open(
            HKEY_CURRENT_USER,
            RUN_KEYS[0],
            KEY_SET_VALUE | KEY_QUERY_VALUE,
        )
        .unwrap();
        for (value_name, command) in [
            (&name, format!("\"{}\" /startup", target.display())),
            (&unrelated, r"C:\Windows\System32\notepad.exe".to_owned()),
        ] {
            let data = wide(&command);
            let value_name = wide(value_name);
            unsafe {
                RegSetValueExW(
                    key,
                    value_name.as_ptr(),
                    0,
                    REG_SZ,
                    data.as_ptr().cast(),
                    (data.len() * 2) as u32,
                )
            };
        }

        let removed = remove_autostarts_for(&target);
        let still_there = |value_name: &str| {
            let value_name = wide(value_name);
            let mut size = 0u32;
            (unsafe {
                RegGetValueW(
                    key,
                    std::ptr::null(),
                    value_name.as_ptr(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut size,
                )
            }) == 0
        };
        let kept = still_there(&unrelated);
        let gone = !still_there(&name);
        let unrelated_wide = wide(&unrelated);
        unsafe {
            RegDeleteValueW(key, unrelated_wide.as_ptr());
            RegCloseKey(key);
        }

        assert!(gone, "the entry launching the removed file is still there");
        assert!(kept, "an unrelated entry was removed");
        assert!(
            removed.iter().any(|entry| entry.ends_with(&name)),
            "{removed:?}"
        );
    }
}
