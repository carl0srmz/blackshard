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

/// A registry key and everything below it, as read at one moment. Key paths are relative to the
/// tree's root ("" is the root itself) and compared ignoring case, as the registry does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    /// Lower-case path to the path as written.
    pub keys: std::collections::BTreeMap<String, String>,
    /// (lower-case key, lower-case name) to the value as written.
    pub values: std::collections::BTreeMap<(String, String), TreeValue>,
    /// False when the walk stopped at a size bound: an incomplete tree is never undone.
    pub complete: bool,
}

/// A value in a [`Tree`]: its key and name as written, its type and its data.
pub type TreeValue = (String, String, u32, Vec<u8>);

/// How much of a tree's change a hunt undoes.
#[derive(Debug, Clone, Copy)]
pub enum TreePolicy {
    /// Everything: keys and values added are removed, changed and removed ones put back.
    UndoAll,
    /// Only values added since the baseline whose data the test condemns; firewall rules, where
    /// legitimate programs add their own too.
    RemoveAddedWhere(fn(&[u8]) -> bool),
}

/// One step of undoing a tree's change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeOp {
    DeleteKey(String),
    DeleteValue(String, String),
    CreateKey(String),
    SetValue(String, String, u32, Vec<u8>),
}

fn parent_of(key: &str) -> Option<&str> {
    if key.is_empty() {
        None
    } else {
        Some(key.rsplit_once('\\').map_or("", |(parent, _)| parent))
    }
}

/// What it takes to turn `current` back into `baseline`. Added keys are removed from the top
/// down, so a key added with children is one deletion; values are only touched in keys that
/// existed before.
pub fn tree_undo(baseline: &Tree, current: &Tree, policy: TreePolicy) -> Vec<TreeOp> {
    if !baseline.complete || !current.complete {
        return Vec::new();
    }
    let mut ops = Vec::new();
    match policy {
        TreePolicy::RemoveAddedWhere(condemns) => {
            for (key, (key_written, name, _, data)) in &current.values {
                if !baseline.values.contains_key(key) && condemns(data) {
                    ops.push(TreeOp::DeleteValue(key_written.clone(), name.clone()));
                }
            }
        }
        TreePolicy::UndoAll => {
            for (key, written) in &current.keys {
                let added = !baseline.keys.contains_key(key);
                let parent_existed =
                    parent_of(key).is_none_or(|parent| baseline.keys.contains_key(parent));
                if added && parent_existed {
                    ops.push(TreeOp::DeleteKey(written.clone()));
                }
            }
            for (key, (key_written, name, _, _)) in &current.values {
                if baseline.keys.contains_key(&key.0) && !baseline.values.contains_key(key) {
                    ops.push(TreeOp::DeleteValue(key_written.clone(), name.clone()));
                }
            }
            for (key, written) in &baseline.keys {
                if !current.keys.contains_key(key) {
                    ops.push(TreeOp::CreateKey(written.clone()));
                }
            }
            for (key, (key_written, name, kind, data)) in &baseline.values {
                let unchanged =
                    current
                        .values
                        .get(key)
                        .is_some_and(|(_, _, current_kind, current_data)| {
                            current_kind == kind && current_data == data
                        });
                if !unchanged {
                    ops.push(TreeOp::SetValue(
                        key_written.clone(),
                        name.clone(),
                        *kind,
                        data.clone(),
                    ));
                }
            }
        }
    }
    ops
}

/// A firewall rule (`v2.x|Action=Allow|...|App=C:\Users\...|...`) that lets in a program kept
/// somewhere a user or download can put one.
fn firewall_rule_for_user_writable_program(data: &[u8]) -> bool {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let rule = String::from_utf16_lossy(&units).to_ascii_lowercase();
    rule.contains("action=allow")
        && rule.split('|').any(|field| {
            field.strip_prefix("app=").is_some_and(|app| {
                ["\\users\\", "\\programdata\\", "\\temp\\", "\\appdata\\"]
                    .iter()
                    .any(|place| app.contains(place))
            })
        })
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
    use super::{tree_undo, Tree, TreeOp, TreePolicy};
    use crate::persistence::{open, subkeys, wide};
    use std::collections::BTreeMap;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
    };

    /// Single values in the machine hive.
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
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
        ),
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "LoadAppInit_DLLs",
        ),
        // What opens a program, script or text file: hijacked so every launch runs the malware.
        (r"SOFTWARE\Classes\exefile\shell\open\command", ""),
        (r"SOFTWARE\Classes\comfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\batfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\cmdfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\regfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\txtfile\shell\open\command", ""),
        (r"SOFTWARE\Classes\.exe", ""),
    ];
    /// Single values in every user's hive: the wallpaper, and the proxy a banking trojan or
    /// adware points the browser through.
    const USER_VALUES: &[(&str, &str)] = &[
        (r"Control Panel\Desktop", "Wallpaper"),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyServer",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyEnable",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyOverride",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "AutoConfigURL",
        ),
    ];
    /// Whole keys in the machine hive, put back as they were with everything below them.
    const MACHINE_TREES: &[(&str, &str, TreePolicy)] = &[
        (
            "Defender policies",
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            TreePolicy::UndoAll,
        ),
        (
            "Defender exclusions",
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
            TreePolicy::UndoAll,
        ),
        (
            "Chrome policies",
            r"SOFTWARE\Policies\Google\Chrome",
            TreePolicy::UndoAll,
        ),
        (
            "Edge policies",
            r"SOFTWARE\Policies\Microsoft\Edge",
            TreePolicy::UndoAll,
        ),
        (
            "Firefox policies",
            r"SOFTWARE\Policies\Mozilla\Firefox",
            TreePolicy::UndoAll,
        ),
        (
            "trusted root certificates",
            r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates",
            TreePolicy::UndoAll,
        ),
        (
            "trusted root certificates set by policy",
            r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates",
            TreePolicy::UndoAll,
        ),
        (
            "Safe Mode start list",
            r"SYSTEM\CurrentControlSet\Control\SafeBoot",
            TreePolicy::UndoAll,
        ),
        ("program launch options (IFEO)", IFEO, TreePolicy::UndoAll),
        (
            "silent process exit monitors",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            TreePolicy::UndoAll,
        ),
        (
            "machine policies",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            TreePolicy::UndoAll,
        ),
        (
            "Windows system policies",
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            TreePolicy::UndoAll,
        ),
        (
            "LSA security packages",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            TreePolicy::UndoAll,
        ),
        (
            "firewall rules",
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
            TreePolicy::RemoveAddedWhere(super::firewall_rule_for_user_writable_program),
        ),
    ];
    /// Whole keys in every user's hive. The `Classes` commands are the registrations UAC
    /// bypasses write (fodhelper, Event Viewer, sdclt) and a per-user program-association hijack.
    const USER_TREES: &[(&str, &str, TreePolicy)] = &[
        (
            "policies",
            r"Software\Microsoft\Windows\CurrentVersion\Policies",
            TreePolicy::UndoAll,
        ),
        (
            "Windows policies",
            r"Software\Policies",
            TreePolicy::UndoAll,
        ),
        (
            "root certificates",
            r"Software\Microsoft\SystemCertificates\Root\Certificates",
            TreePolicy::UndoAll,
        ),
        (
            "UAC bypass through Settings",
            r"Software\Classes\ms-settings\Shell\Open\command",
            TreePolicy::UndoAll,
        ),
        (
            "UAC bypass through Event Viewer",
            r"Software\Classes\mscfile\shell\open\command",
            TreePolicy::UndoAll,
        ),
        (
            "UAC bypass through folders",
            r"Software\Classes\Folder\shell\open\command",
            TreePolicy::UndoAll,
        ),
        (
            "program file association",
            r"Software\Classes\exefile\shell\open\command",
            TreePolicy::UndoAll,
        ),
    ];
    const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    /// Bounds on a tree walk; past them the tree is marked incomplete and left alone.
    const MAX_TREE_DEPTH: usize = 8;
    const MAX_TREE_KEYS: usize = 5_000;
    const MAX_TREE_VALUES: usize = 20_000;

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
        /// Each watched tree: its root, full path, label, policy and contents.
        trees: Vec<(Root, String, String, TreePolicy, Tree)>,
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

    fn locations(users: &[String]) -> Vec<Location> {
        let mut all = Vec::new();
        for (path, name) in MACHINE_VALUES {
            all.push((Root::Machine, path.to_string(), name.to_string()));
        }
        for sid in users {
            for (path, name) in USER_VALUES {
                all.push((Root::Users, format!(r"{sid}\{path}"), name.to_string()));
            }
        }
        all
    }

    fn trees(users: &[String]) -> Vec<(Root, String, String, TreePolicy)> {
        let mut all = Vec::new();
        for (label, path, policy) in MACHINE_TREES {
            all.push((Root::Machine, path.to_string(), label.to_string(), *policy));
        }
        for sid in users {
            for (label, path, policy) in USER_TREES {
                all.push((
                    Root::Users,
                    format!(r"{sid}\{path}"),
                    format!("{label} of {sid}"),
                    *policy,
                ));
            }
        }
        all
    }

    /// Every key and value under `path`, bounded.
    fn read_tree(root: Root, path: &str) -> Tree {
        use windows_sys::Win32::System::Registry::{RegEnumValueW, RegOpenKeyExW};
        const ERROR_FILE_NOT_FOUND: u32 = 2;
        let mut tree = Tree {
            complete: true,
            ..Tree::default()
        };
        let mut pending = vec![(String::new(), 0usize)];
        while let Some((relative, depth)) = pending.pop() {
            let full = if relative.is_empty() {
                path.to_owned()
            } else {
                format!(r"{path}\{relative}")
            };
            let wide_full = wide(&full);
            let mut key: HKEY = 0;
            let opened = unsafe {
                RegOpenKeyExW(
                    root.handle(),
                    wide_full.as_ptr(),
                    0,
                    KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                    &mut key,
                )
            };
            match opened {
                0 => {}
                ERROR_FILE_NOT_FOUND if relative.is_empty() => return tree,
                _ => {
                    tree.complete = false;
                    return tree;
                }
            }
            tree.keys.insert(relative.to_lowercase(), relative.clone());
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
                if status == 259 {
                    break;
                }
                if status != 0 || tree.values.len() >= MAX_TREE_VALUES {
                    // A value too large to read, or too many: this tree is not undone.
                    tree.complete = false;
                    break;
                }
                let name = String::from_utf16_lossy(&name[..name_length as usize]);
                data.truncate(data_length as usize);
                tree.values.insert(
                    (relative.to_lowercase(), name.to_lowercase()),
                    (relative.clone(), name, kind, data),
                );
            }
            unsafe { RegCloseKey(key) };
            if depth >= MAX_TREE_DEPTH {
                if !subkeys(root.handle(), &full).is_empty() {
                    tree.complete = false;
                }
                continue;
            }
            for child in subkeys(root.handle(), &full) {
                if tree.keys.len() + pending.len() >= MAX_TREE_KEYS {
                    tree.complete = false;
                    return tree;
                }
                let child = if relative.is_empty() {
                    child
                } else {
                    format!(r"{relative}\{child}")
                };
                pending.push((child, depth + 1));
            }
        }
        tree
    }

    fn apply(root: Root, path: &str, op: &TreeOp) -> bool {
        use windows_sys::Win32::System::Registry::RegDeleteTreeW;
        let full = |relative: &str| {
            if relative.is_empty() {
                path.to_owned()
            } else {
                format!(r"{path}\{relative}")
            }
        };
        match op {
            TreeOp::DeleteKey(relative) => {
                let target = wide(&full(relative));
                let emptied = unsafe { RegDeleteTreeW(root.handle(), target.as_ptr()) } == 0;
                if !emptied || !relative.is_empty() {
                    return emptied;
                }
                // For the tree's own root, RegDeleteTreeW leaves the key, empty; remove it too.
                let Some((parent, name)) = path.rsplit_once('\\') else {
                    return true;
                };
                use windows_sys::Win32::System::Registry::RegDeleteKeyExW;
                let Some(parent) = open(root.handle(), parent, KEY_QUERY_VALUE) else {
                    return false;
                };
                let name = wide(name);
                let deleted =
                    unsafe { RegDeleteKeyExW(parent, name.as_ptr(), KEY_WOW64_64KEY, 0) } == 0;
                unsafe { RegCloseKey(parent) };
                deleted
            }
            TreeOp::DeleteValue(relative, name) => {
                write(&(root, full(relative), name.clone()), &None)
            }
            TreeOp::CreateKey(relative) => {
                let target = wide(&full(relative));
                let mut key: HKEY = 0;
                let created = unsafe {
                    RegCreateKeyExW(
                        root.handle(),
                        target.as_ptr(),
                        0,
                        std::ptr::null(),
                        0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY,
                        std::ptr::null(),
                        &mut key,
                        std::ptr::null_mut(),
                    )
                };
                if created == 0 {
                    unsafe { RegCloseKey(key) };
                }
                created == 0
            }
            TreeOp::SetValue(relative, name, kind, data) => write(
                &(root, full(relative), name.clone()),
                &Some((*kind, data.clone())),
            ),
        }
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
        for location in locations(&users) {
            match read(&location) {
                Ok(value) => {
                    values.insert(location, value);
                }
                Err(_) => unreadable.push(location),
            }
        }
        let trees = trees(&users)
            .into_iter()
            .map(|(root, path, label, policy)| {
                let tree = read_tree(root, &path);
                (root, path, label, policy, tree)
            })
            .collect();
        Snapshot {
            users,
            values,
            trees,
            unreadable,
        }
    }

    /// Puts every watched value and tree back as the snapshot has it. Users who signed in after
    /// the snapshot have no baseline and are left alone.
    pub fn restore(snapshot: &Snapshot) -> Vec<String> {
        let mut repairs = Vec::new();
        for (root, path, label, policy, baseline) in &snapshot.trees {
            let current = read_tree(*root, path);
            let ops = tree_undo(baseline, &current, *policy);
            if ops.is_empty() {
                continue;
            }
            let undone = ops.iter().filter(|op| apply(*root, path, op)).count();
            if undone < ops.len() {
                log::warn!(
                    r"Undid {undone} of {} changes in {}\{path}",
                    ops.len(),
                    root.name()
                );
            }
            if undone > 0 {
                repairs.push(format!(
                    r"{label}: {undone} change(s) undone ({}\{path})",
                    root.name()
                ));
            }
        }
        for location in locations(&snapshot.users) {
            if snapshot.unreadable.contains(&location) {
                continue;
            }
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

    fn tree(keys: &[&str], values: &[(&str, &str, &[u8])]) -> Tree {
        Tree {
            keys: keys
                .iter()
                .map(|key| (key.to_lowercase(), key.to_string()))
                .collect(),
            values: values
                .iter()
                .map(|(key, name, data)| {
                    (
                        (key.to_lowercase(), name.to_lowercase()),
                        (key.to_string(), name.to_string(), 1, data.to_vec()),
                    )
                })
                .collect(),
            complete: true,
        }
    }

    #[test]
    fn a_tree_is_put_back_as_it_was() {
        let baseline = tree(
            &["", "Exclusions", "Exclusions\\Paths"],
            &[
                ("", "DisableAntiSpyware", b"0"),
                ("Exclusions\\Paths", "C:\\Build", b"0"),
            ],
        );
        let current = tree(
            &[
                "",
                "Exclusions",
                "Exclusions\\Paths",
                "Real-Time Protection",
                "Real-Time Protection\\x",
            ],
            &[
                ("", "DisableAntiSpyware", b"1"),
                ("Exclusions\\Paths", "C:\\Build", b"0"),
                ("Exclusions\\Paths", "C:\\", b"0"),
                ("Real-Time Protection", "DisableRealtimeMonitoring", b"1"),
            ],
        );
        let ops = tree_undo(&baseline, &current, TreePolicy::UndoAll);
        assert!(ops.contains(&TreeOp::DeleteKey("Real-Time Protection".to_owned())));
        assert!(
            !ops.contains(&TreeOp::DeleteKey("Real-Time Protection\\x".to_owned())),
            "removed with its parent"
        );
        assert!(ops.contains(&TreeOp::DeleteValue(
            "Exclusions\\Paths".to_owned(),
            "C:\\".to_owned()
        )));
        assert!(ops.contains(&TreeOp::SetValue(
            String::new(),
            "DisableAntiSpyware".to_owned(),
            1,
            b"0".to_vec()
        )));
        assert!(!ops.iter().any(|op| matches!(op, TreeOp::DeleteValue(_, name) if name == "DisableRealtimeMonitoring")), "its key goes as a whole");
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn a_tree_created_from_nothing_is_removed_and_a_deleted_one_comes_back() {
        let absent = Tree {
            complete: true,
            ..Tree::default()
        };
        let created = tree(
            &["", "ExtensionInstallForcelist"],
            &[("ExtensionInstallForcelist", "1", b"abc;https://x")],
        );
        assert_eq!(
            tree_undo(&absent, &created, TreePolicy::UndoAll),
            vec![TreeOp::DeleteKey(String::new())]
        );
        let ops = tree_undo(&created, &absent, TreePolicy::UndoAll);
        assert!(ops.contains(&TreeOp::CreateKey("ExtensionInstallForcelist".to_owned())));
        assert!(ops.contains(&TreeOp::SetValue(
            "ExtensionInstallForcelist".to_owned(),
            "1".to_owned(),
            1,
            b"abc;https://x".to_vec()
        )));
    }

    #[test]
    fn an_incomplete_tree_is_never_touched() {
        let baseline = tree(&[""], &[]);
        let mut current = tree(&["", "x"], &[]);
        current.complete = false;
        assert!(tree_undo(&baseline, &current, TreePolicy::UndoAll).is_empty());
    }

    #[test]
    fn only_firewall_rules_for_user_writable_programs_added_since_are_removed() {
        let wide =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let baseline = tree(&[""], &[]);
        let mut current = baseline.clone();
        for (name, rule) in [
            ("rat", "v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Users\\x\\AppData\\Roaming\\svc.exe|"),
            ("game", "v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Program Files\\Game\\game.exe|"),
        ] {
            current.values.insert(
                (String::new(), name.to_owned()),
                (String::new(), name.to_owned(), 1, wide(rule)),
            );
        }
        assert_eq!(
            tree_undo(
                &baseline,
                &current,
                TreePolicy::RemoveAddedWhere(firewall_rule_for_user_writable_program)
            ),
            vec![TreeOp::DeleteValue(String::new(), "rat".to_owned())]
        );
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
