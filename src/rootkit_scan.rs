//! Looking for kernel rootkits from user mode.
//!
//! A kernel rootkit (ZeroAccess, Necurs, Purple Fox's driver, the Microsoft-signed FiveSys) runs as
//! a driver and hides what it protects. Two things it cannot fully hide are checked during a turbo
//! hunt:
//!
//! - its processes: a rootkit unlinks them from the list Windows hands out, but they still answer
//!   to their process ID, so every ID is tried and the live ones missing from the list are hidden;
//! - its driver: every loaded kernel driver is scanned, and a convicted one is disabled and
//!   quarantined so it does not load at the next start.
//!
//! A rootkit in the kernel can lie to any of this; it raises the bar, it is not a guarantee. The
//! findings say to finish with an offline scan when one is found.

use std::path::PathBuf;

/// Turns the path Windows reports for a loaded driver into one the file system opens:
/// `\SystemRoot\...`, `\??\C:\...`, `\Windows\...` and plain `C:\...` all occur.
pub fn driver_file(reported: &str, system_root: &str) -> Option<PathBuf> {
    let lower = reported.to_ascii_lowercase();
    let root = system_root.trim_end_matches('\\');
    let path = if lower.starts_with(r"\systemroot\") {
        format!(r"{root}\{}", &reported[r"\SystemRoot\".len()..])
    } else if let Some(rest) = reported.strip_prefix(r"\??\") {
        rest.to_owned()
    } else if lower.starts_with(r"\windows\") {
        format!(r"{root}\{}", &reported[r"\Windows\".len()..])
    } else if reported.as_bytes().get(1) == Some(&b':') {
        reported.to_owned()
    } else if !reported.contains('\\') {
        // A bare name: drivers loaded from the default folder.
        format!(r"{root}\System32\drivers\{reported}")
    } else if !reported.starts_with('\\') {
        // Relative to the Windows folder, as service ImagePaths often are: System32\drivers\x.sys.
        format!(r"{root}\{reported}")
    } else {
        return None;
    };
    Some(PathBuf::from(path))
}

#[cfg(windows)]
pub use platform::hunt;

#[cfg(windows)]
mod platform {
    use super::driver_file;
    use crate::detection::{DetectionEngine, DetectionVerdict};
    use crate::quarantine::QuarantineStore;
    use std::collections::HashSet;
    use windows_sys::Win32::Foundation::CloseHandle;

    /// Process IDs are multiples of four; past this none is handed out on any real machine.
    const HIGHEST_PROCESS_ID: u32 = 0x0004_0000;
    const STILL_ACTIVE: u32 = 259;

    #[link(name = "kernel32")]
    extern "system" {
        fn K32EnumDeviceDrivers(drivers: *mut usize, size: u32, needed: *mut u32) -> i32;
        fn K32GetDeviceDriverFileNameW(driver: usize, name: *mut u16, size: u32) -> u32;
        fn GetExitCodeProcess(process: isize, code: *mut u32) -> i32;
    }

    pub fn hunt(engine: &DetectionEngine, quarantine: &QuarantineStore) -> Vec<String> {
        let mut findings = hidden_processes();
        findings.extend(malicious_drivers(engine, quarantine));
        findings
    }

    fn running(process_id: u32) -> bool {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if handle == 0 {
            return false;
        }
        let mut code = 0u32;
        // An exited process can still be opened while something holds a handle to it.
        let alive = unsafe { GetExitCodeProcess(handle, &mut code) } != 0 && code == STILL_ACTIVE;
        unsafe { CloseHandle(handle) };
        alive
    }

    fn hidden_processes() -> Vec<String> {
        let listed: HashSet<u32> = crate::realtime::running_process_ids().into_iter().collect();
        let candidates: Vec<u32> = (8..=HIGHEST_PROCESS_ID)
            .step_by(4)
            .filter(|process_id| !listed.contains(process_id) && running(*process_id))
            .collect();
        if candidates.is_empty() {
            return Vec::new();
        }
        // Started between the two looks: listed now, so not hidden.
        let listed_again: HashSet<u32> =
            crate::realtime::running_process_ids().into_iter().collect();
        let mut findings = Vec::new();
        for process_id in candidates {
            if listed_again.contains(&process_id) || !running(process_id) {
                continue;
            }
            let image = crate::realtime::process_image_path(process_id)
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "an unreadable program".to_owned());
            log::warn!("PID {process_id} ({image}) is hidden from the process list");
            let outcome = if crate::realtime::terminate_process(process_id).is_some() {
                "stopped"
            } else {
                "could not be stopped"
            };
            findings.push(format!(
                "process {process_id} ({image}) was hidden from the process list, which only a rootkit does; {outcome}. Finish with an offline scan (Microsoft Defender Offline)"
            ));
        }
        findings
    }

    fn loaded_drivers() -> Vec<String> {
        let mut bases = vec![0usize; 2048];
        let mut needed = 0u32;
        let size = (bases.len() * std::mem::size_of::<usize>()) as u32;
        if unsafe { K32EnumDeviceDrivers(bases.as_mut_ptr(), size, &mut needed) } == 0 {
            return Vec::new();
        }
        bases.truncate((needed as usize / std::mem::size_of::<usize>()).min(bases.len()));
        bases
            .into_iter()
            .filter_map(|base| {
                let mut name = vec![0u16; 1024];
                let length = unsafe {
                    K32GetDeviceDriverFileNameW(base, name.as_mut_ptr(), name.len() as u32)
                } as usize;
                (length > 0).then(|| String::from_utf16_lossy(&name[..length]))
            })
            .collect()
    }

    fn malicious_drivers(engine: &DetectionEngine, quarantine: &QuarantineStore) -> Vec<String> {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for reported in loaded_drivers() {
            let Some(file) = driver_file(&reported, &system_root) else {
                continue;
            };
            if !seen.insert(file.to_string_lossy().to_ascii_lowercase()) {
                continue;
            }
            let report = engine.scan_path(&file);
            if report.verdict != DetectionVerdict::Malicious {
                continue;
            }
            let threat = report
                .threat_name
                .clone()
                .unwrap_or_else(|| "Rootkit.Driver".to_owned());
            let disabled = crate::persistence::disable_driver_service(&file);
            let quarantined = report.sha256.as_deref().is_some_and(|sha256| {
                quarantine
                    .quarantine_verified(&file, &threat, 100, sha256, report.file_size, None)
                    .is_ok()
            });
            findings.push(format!(
                "loaded driver {} matches {threat}; {}{}. Restart, then run an offline scan",
                file.display(),
                if disabled.is_empty() {
                    "its service could not be found".to_owned()
                } else {
                    format!("{} will not load again", disabled.join(", "))
                },
                if quarantined {
                    ", and its file is in quarantine"
                } else {
                    ""
                }
            ));
            log::warn!("Malicious driver loaded: {file:?} ({threat})");
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_form_of_a_driver_path_becomes_a_file_path() {
        let root = r"C:\Windows";
        for (reported, expected) in [
            (
                r"\SystemRoot\system32\drivers\ACPI.sys",
                r"C:\Windows\system32\drivers\ACPI.sys",
            ),
            (
                r"\??\C:\ProgramData\x\evil.sys",
                r"C:\ProgramData\x\evil.sys",
            ),
            (
                r"\Windows\System32\drivers\tcpip.sys",
                r"C:\Windows\System32\drivers\tcpip.sys",
            ),
            (r"C:\Drivers\vendor.sys", r"C:\Drivers\vendor.sys"),
            (
                r"System32\drivers\evil.sys",
                r"C:\Windows\System32\drivers\evil.sys",
            ),
            (r"ntoskrnl.exe", r"C:\Windows\System32\drivers\ntoskrnl.exe"),
        ] {
            assert_eq!(
                driver_file(reported, root),
                Some(PathBuf::from(expected)),
                "{reported}"
            );
        }
        assert_eq!(driver_file(r"\Device\Weird\x.sys", root), None);
    }
}
