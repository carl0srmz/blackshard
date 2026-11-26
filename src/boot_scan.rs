//! Looking for bootkits: malware that starts before Windows does.
//!
//! An MBR bootkit (TDL4, Petya's loader) rewrites the first sectors of the boot disk. A UEFI
//! bootkit (BlackLotus) puts its own loader on the EFI system partition, a small FAT volume
//! Windows does not mount, and boots through it. Neither is a file any ordinary scan reaches.
//!
//! The turbo hunt scans the boot region and every file on the EFI system partition with the
//! engine, and points out files where Windows' boot partition normally has none. It repairs
//! nothing here: the boot record comes back from the pause baseline (see `repair`), and a damaged
//! EFI partition is rebuilt with Windows' own `bcdboot`, which the finding says.

/// The GPT partition type of an EFI system partition, as its bytes sit on disk:
/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
pub const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// Files on an EFI system partition that a Windows-only machine does not have, relative to the
/// partition's root and lower case. A Linux or vendor loader explains some of these on a
/// dual-boot machine, so they are reported for a person to judge, not removed.
pub fn esp_oddities(files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter(|file| {
            let file = file.to_ascii_lowercase().replace('/', "\\");
            // A `system32` folder on the EFI partition is where BlackLotus stages its exploit.
            file.starts_with("system32\\")
                // A GRUB or shim loader inside Microsoft's own boot folder is a disguise.
                || (file.starts_with("efi\\microsoft\\boot\\")
                    && (file.ends_with("grubx64.efi") || file.ends_with("shimx64.efi")))
                // Executable EFI code outside the EFI folder is not something Windows puts there.
                || (!file.starts_with("efi\\") && file.ends_with(".efi"))
        })
        .cloned()
        .collect()
}

#[cfg(windows)]
pub use platform::hunt;

#[cfg(windows)]
mod platform {
    use super::{esp_oddities, ESP_TYPE};
    use crate::detection::{DetectionEngine, DetectionVerdict};
    use std::ffi::c_void;
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;

    const MAX_ESP_FILES: usize = 2_000;
    const MAX_ESP_FILE_BYTES: u64 = 64 * 1024 * 1024;

    #[link(name = "kernel32")]
    extern "system" {
        fn FindFirstVolumeW(name: *mut u16, length: u32) -> isize;
        fn FindNextVolumeW(find: isize, name: *mut u16, length: u32) -> i32;
        fn FindVolumeClose(find: isize) -> i32;
    }

    /// Scans the boot region and the EFI system partition. Returns a line for each finding.
    pub fn hunt(engine: &DetectionEngine) -> Vec<String> {
        let mut findings = Vec::new();
        if let Some((disk, region)) = crate::repair::read_boot_region() {
            let report = engine.scan_memory(&region);
            if report.verdict == DetectionVerdict::Malicious {
                findings.push(format!(
                    "boot record of disk {disk} matches {}; it is put back after a pause, otherwise run `bootrec /fixmbr` from Windows recovery",
                    report.threat_name.unwrap_or_else(|| "a bootkit".to_owned())
                ));
            }
        }
        for volume in efi_system_partitions() {
            findings.extend(scan_esp(engine, &volume));
        }
        findings
    }

    /// The `\\?\Volume{...}\` paths of every EFI system partition.
    fn efi_system_partitions() -> Vec<String> {
        let mut volumes = Vec::new();
        let mut name = vec![0u16; 260];
        let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
        if find == -1 {
            return volumes;
        }
        loop {
            let length = name
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(name.len());
            let volume = String::from_utf16_lossy(&name[..length]);
            if is_efi_system_partition(&volume) {
                volumes.push(volume);
            }
            if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), name.len() as u32) } == 0 {
                break;
            }
        }
        unsafe { FindVolumeClose(find) };
        volumes
    }

    fn is_efi_system_partition(volume: &str) -> bool {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
        const PARTITION_STYLE_GPT: u32 = 1;
        // The device itself is the path without its trailing backslash.
        let device = volume.trim_end_matches('\\');
        let Ok(handle) = OpenOptions::new()
            .access_mode(0)
            .share_mode(0x7)
            .open(device)
        else {
            return false;
        };
        // PARTITION_INFORMATION_EX: style at 0, the GPT partition type at 32.
        let mut information = [0u8; 144];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle.as_raw_handle() as isize,
                IOCTL_DISK_GET_PARTITION_INFO_EX,
                std::ptr::null(),
                0,
                information.as_mut_ptr().cast::<c_void>(),
                information.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        ok != 0
            && u32::from_le_bytes(information[..4].try_into().unwrap()) == PARTITION_STYLE_GPT
            && information[32..48] == ESP_TYPE
    }

    fn scan_esp(engine: &DetectionEngine, volume: &str) -> Vec<String> {
        let root = PathBuf::from(volume);
        let mut relative_files = Vec::new();
        let mut findings = Vec::new();
        for entry in walkdir::WalkDir::new(&root)
            .follow_links(false)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .take(MAX_ESP_FILES)
        {
            let Ok(relative) = entry.path().strip_prefix(&root) else {
                continue;
            };
            relative_files.push(relative.to_string_lossy().into_owned());
            if entry
                .metadata()
                .is_ok_and(|meta| meta.len() <= MAX_ESP_FILE_BYTES)
            {
                let report = engine.scan_path(entry.path());
                if report.verdict == DetectionVerdict::Malicious {
                    findings.push(format!(
                        "EFI boot file {} matches {}; rebuild the boot files with `bcdboot C:\\Windows` from an administrator prompt",
                        relative.display(),
                        report.threat_name.unwrap_or_else(|| "a bootkit".to_owned())
                    ));
                }
            }
        }
        for odd in esp_oddities(&relative_files) {
            findings.push(format!(
                "EFI boot partition has {odd}, which a Windows-only machine does not; check it"
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_a_windows_boot_partition_does_not_have_are_pointed_out() {
        let files: Vec<String> = [
            r"EFI\Microsoft\Boot\bootmgfw.efi",
            r"EFI\Microsoft\Boot\BCD",
            r"EFI\Boot\bootx64.efi",
            r"EFI\Microsoft\Boot\grubx64.efi",
            r"system32\winload.efi",
            r"loader.efi",
        ]
        .iter()
        .map(|file| file.to_string())
        .collect();
        assert_eq!(
            esp_oddities(&files),
            vec![
                r"EFI\Microsoft\Boot\grubx64.efi".to_owned(),
                r"system32\winload.efi".to_owned(),
                r"loader.efi".to_owned(),
            ]
        );
    }

    #[test]
    fn the_esp_type_is_the_on_disk_form_of_its_guid() {
        // C12A7328-F81F-11D2-...: the first three fields are stored little-endian.
        assert_eq!(&ESP_TYPE[..4], &0xC12A_7328u32.to_le_bytes());
        assert_eq!(&ESP_TYPE[4..6], &0xF81Fu16.to_le_bytes());
        assert_eq!(&ESP_TYPE[6..8], &0x11D2u16.to_le_bytes());
    }
}
