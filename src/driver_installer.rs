use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const REBOOT_REQUIRED_EXIT_CODE: i32 = 3010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverChange {
    Complete,
    RebootRequired,
}

fn validate_inf_path(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect driver INF {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("the driver INF must be a regular, non-symlink file".to_owned());
    }
    if !path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("blackshard.inf"))
    {
        return Err("the driver package entry point must be named blackshard.inf".to_owned());
    }
    fs::canonicalize(path)
        .map_err(|error| format!("could not resolve driver INF {}: {error}", path.display()))
}

fn validate_installer_owned_inf(path: &Path) -> Result<PathBuf, String> {
    let path = validate_inf_path(path)?;
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("could not resolve the running installer helper: {error}"))?;
    let expected = executable
        .parent()
        .ok_or_else(|| "the running executable has no installation directory".to_owned())?
        .join("DriverPackage")
        .join("blackshard.inf");
    let expected = fs::canonicalize(&expected).map_err(|error| {
        format!(
            "the installer-owned driver package is unavailable at {}: {error}",
            expected.display()
        )
    })?;

    let matches = if cfg!(windows) {
        path.to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    } else {
        path == expected
    };
    if !matches {
        return Err(format!(
            "refusing a driver package outside the installed DriverPackage directory: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn read_inf_altitude(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read driver INF {}: {error}", path.display()))?;
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        let words = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        String::from_utf16(&words)
            .map_err(|error| format!("driver INF is not valid UTF-16LE: {error}"))?
    } else {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
        String::from_utf8(bytes.to_vec())
            .map_err(|error| format!("driver INF is not valid UTF-8/ASCII: {error}"))?
    };

    let mut in_registry_section = false;
    let mut matches = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_registry_section = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case("blackshard.AddRegistry");
            continue;
        }
        if !in_registry_section || line.is_empty() || line.starts_with(';') {
            continue;
        }
        let fields = split_inf_fields(line)?;
        if fields.len() < 5
            || !fields[0].eq_ignore_ascii_case("HKR")
            || !fields[1].eq_ignore_ascii_case(r"Parameters\Instances\blackshard Instance")
            || !fields[2].eq_ignore_ascii_case("Altitude")
        {
            continue;
        }
        let altitude = fields.last().expect("the length was checked").trim();
        if altitude.is_empty()
            || !altitude
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || altitude.bytes().filter(|byte| *byte == b'.').count() > 1
        {
            return Err("the blackshard instance altitude is malformed".to_owned());
        }
        matches.push(altitude.to_owned());
    }
    if matches.len() != 1 {
        return Err(format!(
            "the driver INF must contain exactly one blackshard instance altitude (found {})",
            matches.len()
        ));
    }
    let altitude = matches.remove(0);
    if !cfg!(debug_assertions) {
        let expected = option_env!("BLACKSHARD_MINIFILTER_ALTITUDE").ok_or_else(|| {
            "this release build has no embedded Microsoft-assigned minifilter altitude".to_owned()
        })?;
        if altitude != expected {
            return Err(format!(
                "driver altitude {altitude} does not match the release-bound altitude {expected}"
            ));
        }
    }
    Ok(altitude)
}

pub fn validate_release_inf(path: &Path) -> Result<(), String> {
    let path = validate_inf_path(path)?;
    let declared = read_inf_altitude(&path)?;
    let expected = option_env!("BLACKSHARD_MINIFILTER_ALTITUDE").ok_or_else(|| {
        "this binary has no embedded Microsoft-assigned minifilter altitude".to_owned()
    })?;
    if declared != expected {
        return Err(format!(
            "driver altitude {declared} does not match the binary's release-bound altitude {expected}"
        ));
    }
    Ok(())
}

fn split_inf_fields(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    for character in line.chars() {
        match character {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(field.trim().to_owned());
                field.clear();
            }
            ';' if !quoted => break,
            _ => field.push(character),
        }
    }
    if quoted {
        return Err("the driver INF contains an unterminated quoted field".to_owned());
    }
    fields.push(field.trim().to_owned());
    Ok(fields)
}

#[cfg(windows)]
fn wide(value: &std::ffi::OsStr) -> Result<Vec<u16>, String> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err("driver path contains an embedded NUL".to_owned());
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(windows)]
fn filter_name() -> Vec<u16> {
    "blackshard\0".encode_utf16().collect()
}

#[cfg(windows)]
fn install_legacy_filter_registry(altitude: &str) -> Result<(), String> {
    use std::ffi::c_void;
    use std::ptr;

    type Hkey = isize;
    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002_u32 as isize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            key: Hkey,
            subkey: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            desired: u32,
            security_attributes: *const c_void,
            result: *mut Hkey,
            disposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Hkey,
            value_name: *const u16,
            reserved: u32,
            value_type: u32,
            data: *const u8,
            data_size: u32,
        ) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }

    fn wide_string(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_value(subkey: &str, name: &str, value_type: u32, bytes: &[u8]) -> Result<(), String> {
        let subkey = wide_string(subkey);
        let name = wide_string(name);
        let mut key = 0;
        let create = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if create != 0 {
            return Err(format!(
                "could not create minifilter registry key ({create})"
            ));
        }
        let result = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                value_type,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        unsafe { RegCloseKey(key) };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "could not write minifilter registry value ({result})"
            ))
        }
    }

    fn string_bytes(value: &str) -> Vec<u8> {
        wide_string(value)
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    const SERVICE: &str = r"SYSTEM\CurrentControlSet\Services\blackshard";
    const INSTANCES: &str = r"SYSTEM\CurrentControlSet\Services\blackshard\Instances";
    const INSTANCE: &str =
        r"SYSTEM\CurrentControlSet\Services\blackshard\Instances\blackshard Instance";
    set_value(SERVICE, "DebugFlags", REG_DWORD, &0_u32.to_le_bytes())?;
    set_value(
        SERVICE,
        "SupportedFeatures",
        REG_DWORD,
        &3_u32.to_le_bytes(),
    )?;
    set_value(
        INSTANCES,
        "DefaultInstance",
        REG_SZ,
        &string_bytes("blackshard Instance"),
    )?;
    set_value(INSTANCE, "Altitude", REG_SZ, &string_bytes(altitude))?;
    set_value(INSTANCE, "Flags", REG_DWORD, &0_u32.to_le_bytes())
}

#[cfg(windows)]
pub fn install_driver(inf_path: &Path) -> Result<DriverChange, String> {
    #[link(name = "newdev")]
    extern "system" {
        fn DiInstallDriverW(
            hwnd_parent: isize,
            inf_path: *const u16,
            flags: u32,
            need_reboot: *mut i32,
        ) -> i32;
        fn DiUninstallDriverW(
            hwnd_parent: isize,
            inf_path: *const u16,
            flags: u32,
            need_reboot: *mut i32,
        ) -> i32;
    }
    #[link(name = "FltLib")]
    extern "system" {
        fn FilterLoad(filter_name: *const u16) -> i32;
    }

    let inf_path = validate_installer_owned_inf(inf_path)?;
    let altitude = read_inf_altitude(&inf_path)?;
    let inf_path = wide(inf_path.as_os_str())?;
    let mut reboot = 0;
    let installed = unsafe { DiInstallDriverW(0, inf_path.as_ptr(), 0, &mut reboot) };
    if installed == 0 {
        return Err(format!(
            "Windows rejected the signed driver package: {}",
            io::Error::last_os_error()
        ));
    }

    if let Err(error) = install_legacy_filter_registry(&altitude) {
        let mut rollback_reboot = 0;
        let _ = unsafe { DiUninstallDriverW(0, inf_path.as_ptr(), 0, &mut rollback_reboot) };
        return Err(format!(
            "driver installation was rolled back after compatibility setup failed: {error}"
        ));
    }

    if reboot == 0 {
        let load_result = unsafe { FilterLoad(filter_name().as_ptr()) };

        if load_result != 0 && load_result as u32 != 0x8007_00B7 {
            return Err(format!(
                "the driver was installed but the minifilter could not be loaded (0x{:08X})",
                load_result as u32
            ));
        }
    }

    Ok(if reboot != 0 {
        DriverChange::RebootRequired
    } else {
        DriverChange::Complete
    })
}

#[cfg(windows)]
pub fn uninstall_driver(inf_path: &Path) -> Result<DriverChange, String> {
    #[link(name = "newdev")]
    extern "system" {
        fn DiUninstallDriverW(
            hwnd_parent: isize,
            inf_path: *const u16,
            flags: u32,
            need_reboot: *mut i32,
        ) -> i32;
    }
    #[link(name = "FltLib")]
    extern "system" {
        fn FilterUnload(filter_name: *const u16) -> i32;
    }

    let inf_path = validate_installer_owned_inf(inf_path)?;
    let inf_path = wide(inf_path.as_os_str())?;
    let unload_result = unsafe { FilterUnload(filter_name().as_ptr()) };

    // ERROR_FLT_DO_NOT_DETACH: the running driver protects itself from unloading. Its package is
    // removed anyway; it stays loaded until the next restart and is gone after it.
    if unload_result as u32 == 0x801F_0010 {
        log::warn!("The blackshard minifilter stays loaded until Windows restarts");
    } else if unload_result != 0
        && unload_result as u32 != 0x801F_0013
        && unload_result as u32 != 0x8007_0424
    {
        return Err(format!(
            "the minifilter could not be unloaded safely (0x{:08X})",
            unload_result as u32
        ));
    }

    let mut reboot = 0;
    let removed = unsafe { DiUninstallDriverW(0, inf_path.as_ptr(), 0, &mut reboot) };
    if removed == 0 {
        return Err(format!(
            "Windows could not remove the driver package: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(if reboot != 0 {
        DriverChange::RebootRequired
    } else {
        DriverChange::Complete
    })
}

#[cfg(not(windows))]
pub fn install_driver(_inf_path: &Path) -> Result<DriverChange, String> {
    Err("driver installation is available only on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn uninstall_driver(_inf_path: &Path) -> Result<DriverChange, String> {
    Err("driver removal is available only on Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inf_validation_accepts_only_the_expected_regular_file() {
        let temporary = tempfile::tempdir().unwrap();
        let expected = temporary.path().join("blackshard.inf");
        fs::write(&expected, b"[Version]").unwrap();
        assert!(validate_inf_path(&expected).is_ok());

        let wrong_name = temporary.path().join("other.inf");
        fs::write(&wrong_name, b"[Version]").unwrap();
        assert!(validate_inf_path(&wrong_name).is_err());
        assert!(validate_inf_path(temporary.path()).is_err());
    }

    #[test]
    fn altitude_is_read_from_the_parameters_instance_entry() {
        let temporary = tempfile::tempdir().unwrap();
        let inf = temporary.path().join("blackshard.inf");
        fs::write(
            &inf,
            b"[blackshard.AddRegistry]\r\nHKR,\"Parameters\\Instances\\blackshard Instance\",\"Altitude\",0,\"320000.4242\"\r\n",
        )
        .unwrap();
        assert_eq!(read_inf_altitude(&inf).unwrap(), "320000.4242");
    }

    #[test]
    fn altitude_parser_rejects_duplicates_and_decoys() {
        let temporary = tempfile::tempdir().unwrap();
        let inf = temporary.path().join("blackshard.inf");
        fs::write(
            &inf,
            b"[decoy]\r\nHKR,\"Parameters\\Instances\\blackshard Instance\",\"Altitude\",0,\"1\"\r\n[blackshard.AddRegistry]\r\nHKR,\"Parameters\\Instances\\blackshard Instance\",\"Altitude\",0,\"320000.1\"\r\nHKR,\"Parameters\\Instances\\blackshard Instance\",\"Altitude\",0,\"320000.2\"\r\n",
        )
        .unwrap();
        assert!(read_inf_altitude(&inf).is_err());
    }

    #[test]
    fn release_validation_never_accepts_an_unbound_binary() {
        if option_env!("BLACKSHARD_MINIFILTER_ALTITUDE").is_some() {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        let inf = temporary.path().join("blackshard.inf");
        fs::write(
            &inf,
            b"[blackshard.AddRegistry]\r\nHKR,\"Parameters\\Instances\\blackshard Instance\",\"Altitude\",0,\"320000.4242\"\r\n",
        )
        .unwrap();
        assert!(validate_release_inf(&inf).is_err());
    }
}
