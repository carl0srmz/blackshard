//! Startup entries that would relaunch a file blackshard removed.
//!
//! Quarantining a program leaves whatever it registered to start with Windows pointing at a file
//! that is gone. That is harmless until something puts a file back at that path, and it is clutter
//! either way, so the Run and RunOnce entries that launch it are removed with it: machine-wide,
//! in the 32-bit view, and in every user hive that is loaded.
//!
//! ponytail: Run and RunOnce only. Scheduled tasks, services, Startup-folder shortcuts and WMI
//! subscriptions are the next places to clean, in roughly that order of how often malware uses
//! them. Paths written with 8.3 short names are not matched either.

use std::path::Path;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

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
