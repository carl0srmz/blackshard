//! Putting back what malware changed while it ran: the boot record, and the registry values that
//! show-off malware flips to lock the user out (Task Manager, regedit, the Winlogon shell, debugger
//! hijacks, the wallpaper).
//!
//! The approach is a baseline, not a list of known-bad values: the service records how things were
//! the moment an administrator pauses protection, and the turbo hunt that ends that pause puts back
//! whatever differs. Only that one hunt may use it. A baseline from service start would let a
//! standard user's turbo, days later, write back a backdoor an administrator had since removed, or
//! an old boot loader over a new one; a baseline from the pause only undoes the pause.
use chrono::{DateTime, Utc};
use std::sync::Mutex;

/// The start of the boot disk that is saved: the MBR, the GPT header and partition entries, and
/// the gap boot code lives in. Cut short where the first partition begins, so a write never lands
/// in a volume.
const BOOT_REGION_BYTES: usize = 1024 * 1024;
/// Writes to a raw disk must be whole sectors. A GPT header says the sector size; an MBR does not,
/// so its region is cut to 4096, which covers 512-byte and 4K-native disks alike.
const MBR_ALIGNMENT: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDecision {
    Unchanged,
    /// Overwritten, or broken, while the partition layout is the one saved: put the saved copy back.
    Restore,
    /// A different, valid partition layout. Someone repartitioned the disk; writing the old one
    /// back would destroy it, so it is left alone.
    LayoutChanged,
}

/// Whether sector 0 holds a partition table Windows could boot from: the signature, sane boot
/// flags, and at least one entry with a start and a length. Boot code written over sector 0
/// rarely passes all three.
pub fn partition_table_valid(region: &[u8]) -> bool {
    if region.len() < 512 || region[510..512] != [0x55, 0xAA] {
        return false;
    }
    let mut any = false;
    for entry in region[446..510].as_chunks::<16>().0 {
        if entry[0] != 0 && entry[0] != 0x80 {
            return false;
        }
        if entry[4] == 0 {
            continue;
        }
        let start = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let sectors = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        if start == 0 || sectors == 0 {
            return false;
        }
        any = true;
    }
    any
}

/// The GPT header and the sector size it implies, when the disk is GPT.
fn gpt_header(region: &[u8]) -> Option<(&[u8], usize)> {
    [512usize, 4096].into_iter().find_map(|sector| {
        (region.len() >= sector + 92 && &region[sector..sector + 8] == b"EFI PART")
            .then(|| (&region[sector..sector + 92], sector))
    })
}

/// How much of the start of the disk belongs to no partition, from a healthy copy of it.
pub fn boot_region_len(region: &[u8]) -> usize {
    if let Some((header, sector)) = gpt_header(region) {
        // Every partition entry up to the first usable sector, so the entry array's checksum in
        // the header still holds after a restore.
        let first_usable = u64::from_le_bytes(header[40..48].try_into().unwrap());
        let free =
            usize::try_from(first_usable.saturating_mul(sector as u64)).unwrap_or(usize::MAX);
        return free.min(BOOT_REGION_BYTES).min(region.len()) / sector * sector;
    }
    let free = {
        region[446..510]
            .as_chunks::<16>()
            .0
            .iter()
            .filter(|entry| entry[4] != 0)
            .map(|entry| u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize * 512)
            .min()
            .unwrap_or(0)
    };
    free.min(BOOT_REGION_BYTES).min(region.len()) / MBR_ALIGNMENT * MBR_ALIGNMENT
}

/// Decides whether the saved start of the disk should replace what is there now.
pub fn boot_decision(saved: &[u8], current: &[u8]) -> BootDecision {
    if saved == current {
        return BootDecision::Unchanged;
    }
    if current.len() < 512 || saved.len() < 512 {
        return BootDecision::LayoutChanged;
    }
    let broken = !partition_table_valid(current)
        || (gpt_header(saved).is_some() && gpt_header(current).is_none());
    let same_layout =
        current[446..510] == saved[446..510] && gpt_header(current) == gpt_header(saved);
    if broken || same_layout {
        BootDecision::Restore
    } else {
        BootDecision::LayoutChanged
    }
}

/// Everything recorded about the machine at one moment.
struct Baseline {
    /// The pause it was taken for, as `Settings::paused_at`.
    pause: DateTime<Utc>,
    /// The boot disk's number and the start of it.
    boot: Option<(u32, Vec<u8>)>,
    /// The hosts file, which malware rewrites to block security sites or redirect banks.
    hosts: Option<Vec<u8>>,
    #[cfg(windows)]
    registry: registry::Snapshot,
}

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

/// Records how the machine is now, for the pause that began at `pause`. Replaces any earlier
/// baseline. A boot record that already looks broken is not recorded.
pub fn take_baseline(pause: DateTime<Utc>) {
    let boot = boot_disk::read().ok().and_then(|(disk, region)| {
        if !partition_table_valid(&region) {
            log::warn!("The boot record of disk {disk} does not look healthy; not saving it");
            return None;
        }
        let length = boot_region_len(&region);
        (length > 0).then(|| (disk, region[..length].to_vec()))
    });
    let baseline = Baseline {
        pause,
        boot,
        hosts: hosts_path().and_then(|path| std::fs::read(path).ok()),
        #[cfg(windows)]
        registry: registry::snapshot(),
    };
    *BASELINE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(baseline);
}

fn hosts_path() -> Option<std::path::PathBuf> {
    std::env::var_os("SystemRoot").map(|root| {
        std::path::PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    })
}

/// Puts back whatever differs from the baseline taken when the pause that began at `pause`
/// started, and describes each repair. The baseline is used up: a later hunt repairs nothing until
/// the next pause.
pub fn repair_after_pause(pause: DateTime<Utc>) -> Vec<String> {
    let baseline = {
        let mut slot = BASELINE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match slot.take() {
            Some(baseline) if baseline.pause == pause => baseline,
            other => {
                *slot = other;
                log::warn!("No baseline was recorded for the pause at {pause}; nothing to repair");
                return Vec::new();
            }
        }
    };
    let mut repairs = Vec::new();
    if let (Some(path), Some(saved)) = (hosts_path(), &baseline.hosts) {
        if std::fs::read(&path).ok().as_ref() != Some(saved) {
            match crate::atomic_file::write(&path, saved) {
                Ok(()) => repairs.push(format!("hosts file put back ({})", path.display())),
                Err(error) => log::warn!("Could not put back the hosts file: {error}"),
            }
        }
    }
    if let Some((disk, saved)) = &baseline.boot {
        match boot_disk::read_len(*disk, saved.len()) {
            Ok(current) => match boot_decision(saved, &current) {
                BootDecision::Unchanged => {}
                BootDecision::Restore => match boot_disk::write(*disk, saved) {
                    Ok(()) => repairs.push(format!("boot record of disk {disk} restored")),
                    Err(error) => {
                        log::error!("Could not restore the boot record of disk {disk}: {error}")
                    }
                },
                BootDecision::LayoutChanged => log::warn!(
                    "The partition layout of disk {disk} changed since it was saved; not restoring it"
                ),
            },
            Err(error) => log::warn!("Could not read the boot record of disk {disk}: {error}"),
        }
    }
    #[cfg(windows)]
    repairs.extend(registry::restore(&baseline.registry));
    repairs
}

#[cfg(windows)]
mod boot_disk {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;

    #[repr(C)]
    #[derive(Default)]
    struct StorageDeviceNumber {
        device_type: u32,
        device_number: u32,
        partition_number: u32,
    }

    /// The number of the physical disk Windows booted from.
    fn system_disk() -> io::Result<u32> {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        // No access is needed to ask a volume which disk it is on.
        let volume = OpenOptions::new()
            .access_mode(0)
            .open(format!(r"\\.\{drive}"))?;
        let mut number = StorageDeviceNumber::default();
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                volume.as_raw_handle() as isize,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                std::ptr::null(),
                0,
                (&mut number as *mut StorageDeviceNumber).cast(),
                std::mem::size_of::<StorageDeviceNumber>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(number.device_number)
    }

    fn open(disk: u32, write: bool) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(write)
            .open(format!(r"\\.\PhysicalDrive{disk}"))
    }

    pub fn read() -> io::Result<(u32, Vec<u8>)> {
        let disk = system_disk()?;
        Ok((disk, read_len(disk, super::BOOT_REGION_BYTES)?))
    }

    pub fn read_len(disk: u32, length: usize) -> io::Result<Vec<u8>> {
        let mut region = vec![0u8; length];
        open(disk, false)?.read_exact(&mut region)?;
        Ok(region)
    }

    /// Windows lets SYSTEM write the sectors before the first volume, which is all this writes.
    pub fn write(disk: u32, region: &[u8]) -> io::Result<()> {
        let mut file = open(disk, true)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(region)?;
        file.flush()
    }
}

#[cfg(not(windows))]
mod boot_disk {
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "raw disk access is Windows-only",
        )
    }
    pub fn read() -> io::Result<(u32, Vec<u8>)> {
        Err(unsupported())
    }
    pub fn read_len(_disk: u32, _length: usize) -> io::Result<Vec<u8>> {
        Err(unsupported())
    }
    pub fn write(_disk: u32, _region: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(windows)]
mod registry {
    use crate::persistence::{open, subkeys, wide};
    use std::collections::BTreeMap;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
    };

    /// Values in both the machine hive and every user's.
    const POLICY_VALUES: &[(&str, &str)] = &[
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableTaskMgr",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableRegistryTools",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableLockWorkstation",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableChangePassword",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRun",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDesktop",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoControlPanel",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoClose",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoLogoff",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDrives",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoViewOnDrive",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoFolderOptions",
        ),
        (r"Software\Policies\Microsoft\Windows\System", "DisableCMD"),
    ];
    const MACHINE_VALUES: &[(&str, &str)] = &[
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
        ),
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
        ),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
        ),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
        ),
        // What opens a program, script or text file: hijacked so every launch runs the malware.
        (r"SOFTWARE\Classes\exefile\shell\open\command", ""),
        (r"SOFTWARE\Classes\comfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\batfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\cmdfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\regfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\txtfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\.exe", ""),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "legalnoticecaption",
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "legalnoticetext",
        ),
    ];
    const USER_VALUES: &[(&str, &str)] = &[(r"Control Panel\Desktop", "Wallpaper")];
    const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Root {
        Machine,
        Users,
    }

    impl Root {
        fn handle(self) -> HKEY {
            match self {
                Root::Machine => HKEY_LOCAL_MACHINE,
                Root::Users => HKEY_USERS,
            }
        }
        fn name(self) -> &'static str {
            match self {
                Root::Machine => "HKLM",
                Root::Users => "HKU",
            }
        }
    }

    type Location = (Root, String, String);
    /// A value's type and bytes; `None` when it did not exist.
    type Value = Option<(u32, Vec<u8>)>;

    pub struct Snapshot {
        users: Vec<String>,
        values: BTreeMap<Location, Value>,
        /// Values that could not be read when the snapshot was taken: there is nothing to put
        /// back, so they are left alone.
        unreadable: Vec<Location>,
    }

    /// Signed-in users' hives: `HKU\S-1-5-21-...`, not the service accounts or `_Classes`.
    fn user_sids() -> Vec<String> {
        subkeys(HKEY_USERS, "")
            .into_iter()
            // Local and domain accounts, and Microsoft Entra (Azure AD) accounts.
            .filter(|sid| {
                (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
                    && !sid.ends_with("_Classes")
            })
            .collect()
    }

    fn locations(users: &[String], hijacked: &[String]) -> Vec<Location> {
        let mut all = Vec::new();
        for (path, name) in POLICY_VALUES.iter().chain(MACHINE_VALUES) {
            all.push((Root::Machine, path.to_string(), name.to_string()));
        }
        for sid in users {
            for (path, name) in POLICY_VALUES.iter().chain(USER_VALUES) {
                all.push((Root::Users, format!(r"{sid}\{path}"), name.to_string()));
            }
        }
        for program in hijacked {
            all.push((
                Root::Machine,
                format!(r"{IFEO}\{program}"),
                "Debugger".to_owned(),
            ));
        }
        all
    }

    /// The value, `Ok(None)` when it does not exist, and `Err` for any other failure (access
    /// denied, a damaged hive), so an unreadable value is never mistaken for an absent one and
    /// deleted.
    fn read((root, path, name): &Location) -> Result<Value, u32> {
        use windows_sys::Win32::System::Registry::RegOpenKeyExW;
        const ERROR_FILE_NOT_FOUND: u32 = 2;
        const ERROR_MORE_DATA: u32 = 234;
        let wide_path = wide(path);
        let mut key: HKEY = 0;
        let opened = unsafe {
            RegOpenKeyExW(
                root.handle(),
                wide_path.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        match opened {
            0 => {}
            ERROR_FILE_NOT_FOUND => return Ok(None),
            error => return Err(error),
        }
        let name = wide(name);
        let mut kind = 0u32;
        let mut data = vec![0u8; 64 * 1024];
        let mut status = ERROR_MORE_DATA;
        let mut length = data.len() as u32;
        // A value larger than the buffer is still a value; retried once at its size.
        for _ in 0..2 {
            length = data.len() as u32;
            status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut length,
                )
            };
            if status != ERROR_MORE_DATA || length as usize > 16 * 1024 * 1024 {
                break;
            }
            data.resize(length as usize, 0);
        }
        unsafe { RegCloseKey(key) };
        match status {
            0 => {
                data.truncate(length as usize);
                Ok(Some((kind, data)))
            }
            ERROR_FILE_NOT_FOUND => Ok(None),
            error => Err(error),
        }
    }

    fn write((root, path, name): &Location, value: &Value) -> bool {
        let name = wide(name);
        match value {
            None => {
                let Some(key) = open(root.handle(), path, KEY_SET_VALUE) else {
                    // No key, so no value: already as it was.
                    return true;
                };
                let status = unsafe { RegDeleteValueW(key, name.as_ptr()) };
                unsafe { RegCloseKey(key) };
                // ERROR_FILE_NOT_FOUND: already gone.
                status == 0 || status == 2
            }
            Some((kind, data)) => {
                let path = wide(path);
                let mut key: HKEY = 0;
                let created = unsafe {
                    RegCreateKeyExW(
                        root.handle(),
                        path.as_ptr(),
                        0,
                        std::ptr::null(),
                        0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY,
                        std::ptr::null(),
                        &mut key,
                        std::ptr::null_mut(),
                    )
                };
                if created != 0 {
                    return false;
                }
                let status = unsafe {
                    RegSetValueExW(
                        key,
                        name.as_ptr(),
                        0,
                        *kind,
                        data.as_ptr(),
                        data.len() as u32,
                    )
                };
                unsafe { RegCloseKey(key) };
                status == 0
            }
        }
    }

    pub fn snapshot() -> Snapshot {
        let users = user_sids();
        let mut values = BTreeMap::new();
        let mut unreadable = Vec::new();
        for location in locations(&users, &subkeys(HKEY_LOCAL_MACHINE, IFEO)) {
            match read(&location) {
                Ok(value) => {
                    values.insert(location, value);
                }
                Err(_) => unreadable.push(location),
            }
        }
        Snapshot {
            users,
            values,
            unreadable,
        }
    }

    /// Puts every watched value back as the snapshot has it. Users who signed in after the
    /// snapshot have no baseline and are left alone; a debugger hijack added since is removed.
    pub fn restore(snapshot: &Snapshot) -> Vec<String> {
        let mut programs = subkeys(HKEY_LOCAL_MACHINE, IFEO);
        programs.extend(
            snapshot
                .values
                .keys()
                .filter_map(|(_, path, _)| path.strip_prefix(&format!(r"{IFEO}\")))
                .map(str::to_owned),
        );
        programs.sort_by_key(|program| program.to_lowercase());
        programs.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

        let mut repairs = Vec::new();
        for location in locations(&snapshot.users, &programs) {
            if snapshot.unreadable.contains(&location) {
                continue;
            }
            // A debugger entry for a program with no subkey at the time did not exist then.
            let saved = snapshot.values.get(&location).cloned().flatten();
            match read(&location) {
                Ok(current) if current == saved => continue,
                Ok(_) => {}
                Err(_) => continue,
            }
            let (root, path, name) = &location;
            if write(&location, &saved) {
                repairs.push(format!(r"{name} put back ({}\{path})", root.name()));
            } else {
                log::warn!(r"Could not put back {}\{path}\{name}", root.name());
            }
        }
        repairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A healthy MBR disk: one bootable NTFS partition starting at 1 MiB.
    fn mbr_disk() -> Vec<u8> {
        let mut region = vec![0u8; BOOT_REGION_BYTES];
        region[..4].copy_from_slice(b"\x33\xc0\x8e\xd0");
        let entry = &mut region[446..462];
        entry[0] = 0x80;
        entry[4] = 0x07;
        entry[8..12].copy_from_slice(&2048u32.to_le_bytes());
        entry[12..16].copy_from_slice(&1_000_000u32.to_le_bytes());
        region[510] = 0x55;
        region[511] = 0xAA;
        region
    }

    /// A healthy GPT disk: protective MBR, header at LBA 1, first usable LBA 34.
    fn gpt_disk() -> Vec<u8> {
        let mut region = vec![0u8; BOOT_REGION_BYTES];
        let entry = &mut region[446..462];
        entry[4] = 0xEE;
        entry[8..12].copy_from_slice(&1u32.to_le_bytes());
        entry[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        region[510] = 0x55;
        region[511] = 0xAA;
        region[512..520].copy_from_slice(b"EFI PART");
        region[512 + 40..512 + 48].copy_from_slice(&34u64.to_le_bytes());
        region
    }

    #[test]
    fn the_saved_region_stops_where_the_first_partition_starts() {
        assert_eq!(boot_region_len(&mbr_disk()), 1024 * 1024);
        assert_eq!(boot_region_len(&gpt_disk()), 34 * 512);
        let mut old_alignment = mbr_disk();
        old_alignment[446 + 8..446 + 12].copy_from_slice(&63u32.to_le_bytes());
        assert_eq!(boot_region_len(&old_alignment), 28_672);
    }

    #[test]
    fn overwritten_boot_code_and_a_wiped_table_are_restored() {
        let saved = mbr_disk();
        assert_eq!(boot_decision(&saved, &saved), BootDecision::Unchanged);

        // Boot code replaced, table untouched.
        let mut payload = saved.clone();
        payload[..440].fill(0xCC);
        payload[4096..8192].fill(0x90);
        assert_eq!(boot_decision(&saved, &payload), BootDecision::Restore);

        // The whole first sector written over with code, signature and all.
        let mut wiped = saved.clone();
        wiped[..512].fill(0xEB);
        assert!(!partition_table_valid(&wiped));
        assert_eq!(boot_decision(&saved, &wiped), BootDecision::Restore);
    }

    #[test]
    fn a_destroyed_gpt_header_is_restored() {
        let saved = gpt_disk();
        let mut damaged = saved.clone();
        damaged[512..1024].fill(0);
        assert_eq!(boot_decision(&saved, &damaged), BootDecision::Restore);
    }

    #[test]
    fn a_disk_someone_repartitioned_is_left_alone() {
        let saved = mbr_disk();
        let mut repartitioned = saved.clone();
        repartitioned[446 + 12..446 + 16].copy_from_slice(&2_000_000u32.to_le_bytes());
        assert_eq!(
            boot_decision(&saved, &repartitioned),
            BootDecision::LayoutChanged
        );

        let saved = gpt_disk();
        let mut resized = saved.clone();
        resized[512 + 88..512 + 92].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(boot_decision(&saved, &resized), BootDecision::LayoutChanged);
    }
}
