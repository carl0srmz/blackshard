//! Startup entries that would relaunch a file blackshard removed.
//!
//! Quarantining a program leaves whatever it registered to start with Windows pointing at a file
//! that is gone. That is harmless until something puts a file back at that path, and it is clutter
//! either way, so the Run and RunOnce entries that launch it are removed with it: machine-wide,
//! in the 32-bit view, and in every user hive that is loaded.
//!
//! Scheduled tasks, Win32 services (by program or service DLL), Startup-folder items, AppInit
//! DLLs, the Winlogon shell, debugger and silent-exit hijacks, per-user COM hijacks, Active Setup,
//! BITS jobs and WMI subscriptions that launch the file are removed too. [`sweep_autostarts`]
//! removes, from the same places, whatever the command-line rules condemn, which is how fileless
//! malware is cleaned up. Paths written with 8.3 short names are not matched.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegGetValueW,
    RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS,
    KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, RRF_RT_DWORD,
    RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
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
    removed.extend(remove_startup_items(&target));
    removed
}

const STARTUP_EXTENSIONS: [&str; 6] = ["lnk", "bat", "cmd", "vbs", "url", "js"];
const MAX_STARTUP_ITEM_BYTES: u64 = 1024 * 1024;

/// Deletes shortcuts and scripts in the all-users and per-user Startup folders that name `target`.
fn remove_startup_items(target: &str) -> Vec<String> {
    let mut folders = Vec::new();
    if let Some(data) = std::env::var_os("ProgramData") {
        folders.push(PathBuf::from(data).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    for sid in subkeys(HKEY_USERS, "") {
        if sid.ends_with("_Classes") {
            continue;
        }
        if let Some(profile) = profile_path(&sid) {
            folders.push(
                PathBuf::from(profile)
                    .join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
            );
        }
    }
    let mut removed = Vec::new();
    for folder in folders {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_TASK_FILES) {
            let path = entry.path();
            let known = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    STARTUP_EXTENSIONS
                        .iter()
                        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
                });
            // A reparse point could aim the delete at a file elsewhere.
            let plain = entry
                .metadata()
                .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_STARTUP_ITEM_BYTES);
            if !known || !plain {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if crate::remediation::item_launches(&bytes, target)
                && std::fs::remove_file(&path).is_ok()
            {
                removed.push(format!("Startup folder: {}", path.display()));
            }
        }
    }
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
    remove_tasks_where(&|line| launches(line, None, target))
}

/// Deletes every scheduled task with an action `condemns` says is malicious.
fn remove_tasks_where(condemns: &dyn Fn(&str) -> bool) -> Vec<String> {
    let tasks_folder = windows_folder().join(r"System32\Tasks");
    let mut found = Vec::new();
    collect_task_files(&tasks_folder, &tasks_folder, 0, &mut found);

    let schtasks = windows_folder().join(r"System32\schtasks.exe");
    let mut removed = Vec::new();
    for (name, definition) in found {
        let launches_target = crate::remediation::task_command_lines(&definition)
            .iter()
            .any(|line| condemns(line));
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
    remove_services_where(&|command| launches(command, None, target))
}

/// Stops and deletes every Win32 service whose program or DLL `condemns` says is malicious.
fn remove_services_where(condemns: &dyn Fn(&str) -> bool) -> Vec<String> {
    const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
    let sc = windows_folder().join(r"System32\sc.exe");
    let mut removed = Vec::new();
    for service in subkeys(HKEY_LOCAL_MACHINE, SERVICES) {
        let key = format!(r"{SERVICES}\{service}");
        let service_type = registry_dword(HKEY_LOCAL_MACHINE, &key, "Type").unwrap_or(0);
        if service_type & SERVICE_WIN32_OWN_OR_SHARE == 0 {
            continue;
        }
        let image_path = registry_string(HKEY_LOCAL_MACHINE, &key, "ImagePath");
        // A service hosted in svchost runs its DLL, named by ServiceDll, which is how Conficker
        // and Emotet-style loaders persist without an executable of their own.
        let service_dll = registry_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"{key}\Parameters"),
            "ServiceDll",
        )
        .or_else(|| registry_string(HKEY_LOCAL_MACHINE, &key, "ServiceDll"));
        let Some(image_path) = [image_path, service_dll]
            .into_iter()
            .flatten()
            .find(|command| condemns(command))
        else {
            continue;
        };
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

const RUN_KEYS: [&str; 5] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    // Group Policy's Run list: the same as Run, and missed by anything that only looks there.
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
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
    let mut removed = more_autostarts_for(&target);
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
    clean_key_where(root, root_name, path, profile, &|command, profile| {
        launches(command, profile, target)
    })
}

/// Deletes every string value under `path` whose command `condemns` says is malicious.
fn clean_key_where(
    root: HKEY,
    root_name: &str,
    path: &str,
    profile: Option<&str>,
    condemns: &dyn Fn(&str, Option<&str>) -> bool,
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
        if condemns(&command, profile) {
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
    crate::remediation::command_names_path(&comparable(&expand(command, profile)), target)
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

/// The profile folder of every local, domain and Microsoft Entra account on the machine, by SID.
pub(crate) fn user_profiles() -> Vec<(String, PathBuf)> {
    subkeys(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
    )
    .into_iter()
    .filter(|sid| sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
    .filter_map(|sid| profile_path(&sid).map(|path| (sid, PathBuf::from(path))))
    .collect()
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

pub(crate) fn subkeys(root: HKEY, path: &str) -> Vec<String> {
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

pub(crate) fn open(root: HKEY, path: &str, access: u32) -> Option<HKEY> {
    let path = wide(path);
    let mut key: HKEY = 0;
    (unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut key) } == 0)
        .then_some(key)
}

pub(crate) fn wide(text: &str) -> Vec<u16> {
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

/// Registered with Windows to run a DLL in every program, or a program at sign-in.
const APPINIT_KEYS: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
];
const WINLOGON_KEYS: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
];
const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const SILENT_PROCESS_EXIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const ACTIVE_SETUP_KEYS: [&str; 2] = [
    r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
];
/// More than a user hive ever holds legitimately; a bound on how long a walk can take.
const MAX_SUBKEYS: usize = 20_000;

/// The places beyond Run keys, tasks, services and Startup folders that make Windows start a
/// program or load a DLL: AppInit_DLLs, the per-user `Load` and `Run` values, the Winlogon shell
/// and Userinit, debugger and silent-exit hijacks, per-user COM hijacks, Active Setup, BITS jobs
/// and WMI subscriptions. Removes those that name `target`.
fn more_autostarts_for(target: &str) -> Vec<String> {
    let names = |command: &str, profile: Option<&str>| launches(command, profile, target);
    let mut removed = Vec::new();
    for key in APPINIT_KEYS {
        if let Some(value) = registry_string(HKEY_LOCAL_MACHINE, key, "AppInit_DLLs") {
            let kept: Vec<&str> = value
                .split([' ', ','])
                .filter(|dll| !dll.is_empty() && !names(dll, None))
                .collect();
            if kept.len()
                != value
                    .split([' ', ','])
                    .filter(|dll| !dll.is_empty())
                    .count()
                && set_string(HKEY_LOCAL_MACHINE, key, "AppInit_DLLs", &kept.join(" "))
            {
                removed.push(format!(r"HKLM\{key}: AppInit_DLLs entry"));
            }
        }
    }
    for key in WINLOGON_KEYS {
        let system32 = windows_folder().join("system32");
        for (value, default) in [
            ("Shell", "explorer.exe".to_owned()),
            ("Userinit", format!(r"{}\userinit.exe,", system32.display())),
        ] {
            if registry_string(HKEY_LOCAL_MACHINE, key, value)
                .is_some_and(|command| names(&command, None))
                && set_string(HKEY_LOCAL_MACHINE, key, value, &default)
            {
                removed.push(format!(r"HKLM\{key}: {value} reset to {default}"));
            }
        }
    }
    for program in subkeys(HKEY_LOCAL_MACHINE, IFEO)
        .into_iter()
        .take(MAX_SUBKEYS)
    {
        let key = format!(r"{IFEO}\{program}");
        if registry_string(HKEY_LOCAL_MACHINE, &key, "Debugger")
            .is_some_and(|command| names(&command, None))
            && delete_value(HKEY_LOCAL_MACHINE, &key, "Debugger")
        {
            removed.push(format!("debugger hijack of {program}"));
        }
    }
    for program in subkeys(HKEY_LOCAL_MACHINE, SILENT_PROCESS_EXIT)
        .into_iter()
        .take(MAX_SUBKEYS)
    {
        let key = format!(r"{SILENT_PROCESS_EXIT}\{program}");
        if registry_string(HKEY_LOCAL_MACHINE, &key, "MonitorProcess")
            .is_some_and(|command| names(&command, None))
            && delete_tree(HKEY_LOCAL_MACHINE, &key)
        {
            removed.push(format!("silent-exit hijack of {program}"));
        }
    }
    for key in ACTIVE_SETUP_KEYS {
        for component in subkeys(HKEY_LOCAL_MACHINE, key)
            .into_iter()
            .take(MAX_SUBKEYS)
        {
            let path = format!(r"{key}\{component}");
            if registry_string(HKEY_LOCAL_MACHINE, &path, "StubPath")
                .is_some_and(|command| names(&command, None))
                && delete_tree(HKEY_LOCAL_MACHINE, &path)
            {
                removed.push(format!("Active Setup component {component}"));
            }
        }
    }
    for sid in subkeys(HKEY_USERS, "") {
        if let Some(user) = sid.strip_suffix("_Classes") {
            // A per-user COM registration shadows the machine's: a hijack needs no administrator.
            let profile = profile_path(user);
            let classes = format!(r"{sid}\CLSID");
            for clsid in subkeys(HKEY_USERS, &classes).into_iter().take(MAX_SUBKEYS) {
                let hijacked = ["InprocServer32", "LocalServer32"].iter().any(|server| {
                    registry_string(HKEY_USERS, &format!(r"{classes}\{clsid}\{server}"), "")
                        .is_some_and(|command| names(&command, profile.as_deref()))
                });
                if hijacked && delete_tree(HKEY_USERS, &format!(r"{classes}\{clsid}")) {
                    removed.push(format!("per-user COM registration {clsid}"));
                }
            }
            continue;
        }
        let profile = profile_path(&sid);
        let key = format!(r"{sid}\Software\Microsoft\Windows NT\CurrentVersion\Windows");
        for value in ["Load", "Run"] {
            if registry_string(HKEY_USERS, &key, value)
                .is_some_and(|command| names(&command, profile.as_deref()))
                && delete_value(HKEY_USERS, &key, value)
            {
                removed.push(format!(r"HKU\{key}: {value}"));
            }
        }
    }
    removed.extend(cancel_bits_jobs_where(&|command| names(command, None)));
    removed.extend(remove_wmi_consumers_where(&|command| names(command, None)));
    removed
}

/// Removes every autostart, wherever Windows keeps it, whose command the command-line rules
/// condemn: a Run value that runs JavaScript through rundll32 (Poweliks), mshta fetching a page,
/// PowerShell downloading and running code. Fileless malware has no file to quarantine; this
/// entry is all there is of it on disk.
pub fn sweep_autostarts() -> Vec<String> {
    let condemns = |command: &str, profile: Option<&str>| {
        crate::command_rules::judge_autostart(&expand(command, profile)).is_some()
    };
    let mut removed = Vec::new();
    for key in RUN_KEYS {
        removed.extend(clean_key_where(
            HKEY_LOCAL_MACHINE,
            "HKLM",
            key,
            None,
            &condemns,
        ));
    }
    for sid in subkeys(HKEY_USERS, "") {
        if sid.ends_with("_Classes") {
            continue;
        }
        let profile = profile_path(&sid);
        for key in RUN_KEYS {
            removed.extend(clean_key_where(
                HKEY_USERS,
                "HKU",
                &format!(r"{sid}\{key}"),
                profile.as_deref(),
                &condemns,
            ));
        }
        let key = format!(r"{sid}\Software\Microsoft\Windows NT\CurrentVersion\Windows");
        for value in ["Load", "Run"] {
            if registry_string(HKEY_USERS, &key, value)
                .is_some_and(|command| condemns(&command, profile.as_deref()))
                && delete_value(HKEY_USERS, &key, value)
            {
                removed.push(format!(r"HKU\{key}: {value}"));
            }
        }
    }
    let by_rule = |command: &str| condemns(command, None);
    removed.extend(remove_tasks_where(&by_rule));
    removed.extend(remove_services_where(&by_rule));
    removed.extend(cancel_bits_jobs_where(&by_rule));
    removed.extend(remove_wmi_consumers_where(&|command| {
        by_rule(command)
            || crate::command_rules::judge_script(&command.to_ascii_lowercase()).is_some()
    }));
    removed
}

fn set_string(root: HKEY, path: &str, name: &str, value: &str) -> bool {
    let Some(key) = open(root, path, KEY_SET_VALUE) else {
        return false;
    };
    let name = wide(name);
    let data = wide(value);
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(key) };
    status == 0
}

fn delete_value(root: HKEY, path: &str, name: &str) -> bool {
    let Some(key) = open(root, path, KEY_SET_VALUE) else {
        return false;
    };
    let name = wide(name);
    let status = unsafe { RegDeleteValueW(key, name.as_ptr()) };
    unsafe { RegCloseKey(key) };
    status == 0
}

fn delete_tree(root: HKEY, path: &str) -> bool {
    let path = wide(path);
    unsafe { RegDeleteTreeW(root, path.as_ptr()) == 0 }
}

/// Runs a fixed PowerShell script, with anything that came from the machine passed in
/// environment variables rather than written into the script, so a hostile name cannot become
/// code run as SYSTEM.
fn run_powershell(script: &str, variables: &[(&str, &str)]) -> Option<String> {
    let powershell = windows_folder().join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = Command::new(powershell);
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    for (name, value) in variables {
        command.env(name, value);
    }
    let output = command.output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// What a WMI event consumer runs: `CommandLineEventConsumer`s run a program, and
/// `ActiveScriptEventConsumer`s run script; both are how fileless malware outlives a reboot.
/// Each line is `class<TAB>base64(name)<TAB>base64(command or script)`, so nothing a consumer
/// contains can break the format.
const LIST_WMI_CONSUMERS: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
function b($v) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$v)) }
foreach ($c in Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer) {
  [Console]::Out.WriteLine('CommandLineEventConsumer' + "`t" + (b $c.Name) + "`t" + (b ([string]$c.ExecutablePath + ' ' + [string]$c.CommandLineTemplate)))
}
foreach ($c in Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer) {
  [Console]::Out.WriteLine('ActiveScriptEventConsumer' + "`t" + (b $c.Name) + "`t" + (b ([string]$c.ScriptFileName + ' ' + [string]$c.ScriptText)))
}"#;

/// Removes one consumer, the bindings that fire it, and the filters only they used.
const REMOVE_WMI_CONSUMER: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$class = $env:BLACKSHARD_WMI_CLASS; $name = $env:BLACKSHARD_WMI_NAME
foreach ($binding in Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding) {
  if ($binding.Consumer.Name -eq $name) {
    $filter = $binding.Filter.Name
    Remove-CimInstance -InputObject $binding
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $filter } | Remove-CimInstance
  }
}
Get-CimInstance -Namespace root/subscription -ClassName $class | Where-Object { $_.Name -eq $name } | Remove-CimInstance"#;

fn remove_wmi_consumers_where(condemns: &dyn Fn(&str) -> bool) -> Vec<String> {
    use base64::Engine;
    let decode = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    };
    let Some(listing) = run_powershell(LIST_WMI_CONSUMERS, &[]) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split('\t');
        let (Some(class), Some(name), Some(command)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !matches!(
            class,
            "CommandLineEventConsumer" | "ActiveScriptEventConsumer"
        ) {
            continue;
        }
        let (Some(name), Some(command)) = (decode(name), decode(command)) else {
            continue;
        };
        if condemns(&command)
            && run_powershell(
                REMOVE_WMI_CONSUMER,
                &[
                    ("BLACKSHARD_WMI_CLASS", class),
                    ("BLACKSHARD_WMI_NAME", &name),
                ],
            )
            .is_some()
        {
            log::warn!("Removed WMI {class} {name}: {command}");
            removed.push(format!("WMI {class}: {name}"));
        }
    }
    removed
}

/// Cancels BITS jobs, in every account, whose completion command `condemns` says is malicious:
/// a BITS job can rerun its command each time it finishes, which some loaders use to persist.
fn cancel_bits_jobs_where(condemns: &dyn Fn(&str) -> bool) -> Vec<String> {
    let bitsadmin = windows_folder().join(r"System32\bitsadmin.exe");
    let Ok(output) = Command::new(&bitsadmin)
        .args(["/list", "/allusers", "/verbose"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return Vec::new();
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    let mut removed = Vec::new();
    for job in crate::remediation::bits_jobs(&listing) {
        if !condemns(&job.notify_command) {
            continue;
        }
        let cancelled = Command::new(&bitsadmin)
            .args(["/cancel", &job.guid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .is_ok_and(|status| status.success());
        if cancelled {
            log::warn!("Cancelled BITS job {}: {}", job.guid, job.notify_command);
            removed.push(format!("BITS job {}", job.guid));
        }
    }
    removed
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
