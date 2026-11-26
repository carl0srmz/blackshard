//! Looking for malware in the memory of running programs.
//!
//! A Cobalt Strike beacon, a Sliver or Meterpreter implant, an infostealer unpacked by its loader,
//! or code injected into Explorer never needs to exist as a file: it is decrypted straight into a
//! process. File scans cannot see it. During a turbo hunt the executable memory of every process
//! the service can open is read and judged:
//!
//! - a signature or rule match there convicts the code;
//! - a whole program image in memory no file backs is how reflective loaders work, and is reported
//!   even without a match.
//!
//! Only executable memory that is private or mapped is read. Ordinary DLLs (image memory) are
//! files the hunt already scanned, and data memory is not code.

/// `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`.
const EXECUTABLE: u32 = 0x10 | 0x20 | 0x40 | 0x80;
const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x2_0000;
const MEM_MAPPED: u32 = 0x4_0000;
/// `PAGE_GUARD`: reading it would trip the program's own guard.
const PAGE_GUARD: u32 = 0x100;

/// Whether a region is code that no file on disk accounts for.
pub fn unbacked_code(state: u32, protect: u32, kind: u32) -> bool {
    state == MEM_COMMIT
        && protect & EXECUTABLE != 0
        && protect & PAGE_GUARD == 0
        && (kind == MEM_PRIVATE || kind == MEM_MAPPED)
}

/// Whether memory starts with a loaded Windows program image: `MZ`, a PE header where the DOS
/// header says, and a machine type Windows runs. Reflective loaders copy one of these into memory
/// they allocated themselves; the system loader never puts one in private memory.
pub fn looks_like_loaded_image(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let Some(header) = bytes.get(offset..offset + 6) else {
        return false;
    };
    let machine = u16::from_le_bytes([header[4], header[5]]);
    &header[..4] == b"PE\0\0" && matches!(machine, 0x014c | 0x8664 | 0xaa64)
}

/// What the hunt found in one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryFinding {
    pub process_id: u32,
    pub image: String,
    pub base: usize,
    pub size: usize,
    /// The engine's name for what matched, or `None` for an image with no match.
    pub threat: Option<String>,
}

#[cfg(windows)]
pub use platform::hunt;

#[cfg(windows)]
mod platform {
    use super::{looks_like_loaded_image, unbacked_code, MemoryFinding};
    use crate::detection::{DetectionEngine, DetectionVerdict};
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

    /// Never more than this of one region is read.
    const MAX_REGION_BYTES: usize = 16 * 1024 * 1024;
    /// Never more than this of one process: JIT-heavy programs (browsers, .NET) hold a lot.
    const MAX_PROCESS_BYTES: usize = 128 * 1024 * 1024;
    /// The whole hunt reads at most this much, so it stays a matter of seconds.
    const MAX_TOTAL_BYTES: usize = 768 * 1024 * 1024;

    #[repr(C)]
    #[derive(Default)]
    struct MemoryBasicInformation {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    #[repr(C)]
    struct ThreadEntry {
        size: u32,
        usage: u32,
        thread_id: u32,
        owner_process_id: u32,
        base_priority: i32,
        delta_priority: i32,
        flags: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualQueryEx(
            process: HANDLE,
            address: *const c_void,
            information: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn ReadProcessMemory(
            process: HANDLE,
            address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> HANDLE;
        fn Thread32First(snapshot: HANDLE, entry: *mut ThreadEntry) -> i32;
        fn Thread32Next(snapshot: HANDLE, entry: *mut ThreadEntry) -> i32;
        fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> HANDLE;
        fn TerminateThread(thread: HANDLE, exit_code: u32) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationThread(
            thread: HANDLE,
            class: u32,
            information: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Reads the executable memory of every process this service can open, judges it, and stops
    /// what it convicts. Returns a line for each thing it stopped or found.
    pub fn hunt(engine: &DetectionEngine, first: &[u32]) -> Vec<String> {
        use windows_sys::Win32::System::Threading::OpenProcess;
        const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
        const PROCESS_VM_READ: u32 = 0x0010;

        let mut order: Vec<u32> = first.to_vec();
        order.extend(
            crate::realtime::running_process_ids()
                .into_iter()
                .filter(|process_id| !first.contains(process_id)),
        );
        let mut lines = Vec::new();
        let mut total = 0usize;
        for process_id in order {
            if process_id <= 4 || process_id == std::process::id() || total >= MAX_TOTAL_BYTES {
                continue;
            }
            let handle =
                unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id) };
            if handle == 0 {
                continue;
            }
            let process = Handle(handle);
            let image = crate::realtime::process_image_path(process_id)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            for finding in scan_process(engine, &process, process_id, &image, &mut total) {
                lines.extend(respond(&finding, first.contains(&process_id)));
            }
        }
        lines
    }

    fn scan_process(
        engine: &DetectionEngine,
        process: &Handle,
        process_id: u32,
        image: &str,
        total: &mut usize,
    ) -> Vec<MemoryFinding> {
        let mut findings = Vec::new();
        let mut address = 0usize;
        let mut read_here = 0usize;
        loop {
            let mut region = MemoryBasicInformation::default();
            let written = unsafe {
                VirtualQueryEx(
                    process.0,
                    address as *const c_void,
                    &mut region,
                    std::mem::size_of::<MemoryBasicInformation>(),
                )
            };
            if written == 0 || region.region_size == 0 {
                break;
            }
            let next = region.base_address.saturating_add(region.region_size);
            if next <= address {
                break;
            }
            address = next;
            if !unbacked_code(region.state, region.protect, region.kind) {
                continue;
            }
            let length = region
                .region_size
                .min(MAX_REGION_BYTES)
                .min(MAX_PROCESS_BYTES.saturating_sub(read_here))
                .min(MAX_TOTAL_BYTES.saturating_sub(*total));
            if length == 0 {
                break;
            }
            let mut bytes = vec![0u8; length];
            let mut read = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    process.0,
                    region.base_address as *const c_void,
                    bytes.as_mut_ptr().cast(),
                    length,
                    &mut read,
                )
            };
            if ok == 0 || read == 0 {
                continue;
            }
            bytes.truncate(read);
            read_here += read;
            *total += read;
            let report = engine.scan_memory(&bytes);
            let threat = (report.verdict == DetectionVerdict::Malicious).then(|| {
                report
                    .threat_name
                    .unwrap_or_else(|| "Memory.Malicious".to_owned())
            });
            if threat.is_some() || looks_like_loaded_image(&bytes) {
                findings.push(MemoryFinding {
                    process_id,
                    image: image.to_owned(),
                    base: region.base_address,
                    size: region.region_size,
                    threat,
                });
            }
        }
        findings
    }

    /// Stops convicted code. In a program that is not Windows' own, the whole process goes; in
    /// Windows' own (Explorer, a service host), only the threads that started in the convicted
    /// memory, since killing those processes takes the desktop or a service with it. A loaded
    /// image with no signature match is reported, and stopped only in an unsigned program that
    /// started during the pause.
    fn respond(finding: &MemoryFinding, started_during_pause: bool) -> Vec<String> {
        let path = std::path::Path::new(&finding.image);
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("process {}", finding.process_id));
        let signed = crate::trust::verify_file_cached(path).is_trusted();
        let system = crate::realtime::is_protected_system_image(path);
        let what = finding
            .threat
            .clone()
            .unwrap_or_else(|| "a program image loaded straight into memory".to_owned());
        log::warn!(
            "Memory of PID {} ({}) at {:#x} (+{:#x}): {what}",
            finding.process_id,
            finding.image,
            finding.base,
            finding.size
        );
        // Packed and protected legitimate programs unpack themselves this way too, so an image
        // with no match only stops an unsigned program that started during the pause.
        if finding.threat.is_none() && (signed || !started_during_pause) {
            return vec![format!("{name}: {what}, left running; check it")];
        }
        if system {
            let stopped = kill_threads_in(finding.process_id, finding.base, finding.size);
            return vec![format!(
                "{name}: {what}, {stopped} injected thread(s) stopped"
            )];
        }
        match crate::realtime::terminate_process(finding.process_id) {
            Some(_) => vec![format!("{name}: {what}, program stopped")],
            None => vec![format!("{name}: {what}, could not be stopped")],
        }
    }

    /// Terminates the threads of `process_id` whose start address lies in `[base, base + size)`.
    fn kill_threads_in(process_id: u32, base: usize, size: usize) -> usize {
        const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        const THREAD_TERMINATE: u32 = 0x0001;
        /// `THREADINFOCLASS::ThreadQuerySetWin32StartAddress`.
        const THREAD_START_ADDRESS: u32 = 9;
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == -1 || snapshot == 0 {
            return 0;
        }
        let snapshot = Handle(snapshot);
        let mut entry = ThreadEntry {
            size: std::mem::size_of::<ThreadEntry>() as u32,
            usage: 0,
            thread_id: 0,
            owner_process_id: 0,
            base_priority: 0,
            delta_priority: 0,
            flags: 0,
        };
        let mut stopped = 0;
        let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
        while more {
            if entry.owner_process_id == process_id {
                let thread = unsafe {
                    OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_TERMINATE,
                        0,
                        entry.thread_id,
                    )
                };
                if thread != 0 {
                    let thread = Handle(thread);
                    let mut start = 0usize;
                    let status = unsafe {
                        NtQueryInformationThread(
                            thread.0,
                            THREAD_START_ADDRESS,
                            (&mut start as *mut usize).cast(),
                            std::mem::size_of::<usize>() as u32,
                            std::ptr::null_mut(),
                        )
                    };
                    if status >= 0
                        && start >= base
                        && start < base.saturating_add(size)
                        && unsafe { TerminateThread(thread.0, 1) } != 0
                    {
                        stopped += 1;
                    }
                }
            }
            more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
        }
        stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn a_program_image_in_memory_is_recognised() {
        assert!(looks_like_loaded_image(&image(0x8664)));
        assert!(looks_like_loaded_image(&image(0x014c)));
        assert!(
            !looks_like_loaded_image(&image(0x1234)),
            "not a machine Windows runs"
        );
        let mut truncated = image(0x8664);
        truncated[0x3C..0x40].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(!looks_like_loaded_image(&truncated));
        assert!(!looks_like_loaded_image(b"MZ"));
        assert!(
            !looks_like_loaded_image(&[0x90; 0x200]),
            "shellcode without headers"
        );
    }

    #[test]
    fn only_unbacked_executable_memory_is_read() {
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_READWRITE: u32 = 0x04;
        const MEM_IMAGE: u32 = 0x100_0000;
        assert!(unbacked_code(
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
            MEM_PRIVATE
        ));
        assert!(unbacked_code(MEM_COMMIT, 0x20, MEM_MAPPED));
        assert!(
            !unbacked_code(MEM_COMMIT, 0x20, MEM_IMAGE),
            "a DLL loaded from a file"
        );
        assert!(
            !unbacked_code(MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
            "data"
        );
        assert!(
            !unbacked_code(0x2000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
            "reserved only"
        );
        assert!(
            !unbacked_code(MEM_COMMIT, 0x20 | 0x100, MEM_PRIVATE),
            "guard page"
        );
    }
}
