//! A safety copy of user documents, so ransomware's damage can be undone.
//!
//! Ransomware deletes shadow copies before it starts, so blackshard keeps its own. The first time
//! an unsigned or unknown program touches a protected document, the service saves the original
//! here, before the driver lets the write, rename or delete through. If the program is then
//! convicted as ransomware, [`RollbackVault::restore`] puts every saved file back.
//!
//! The vault lives in the administrator-only `State` folder and is bounded in every direction:
//! file size, files and bytes per program, total bytes, and age. It is a short-lived safety net,
//! not a backup.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// A file larger than this is not saved: the copy happens while the driver waits for a reply.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES_PER_PROCESS: usize = 256;
const MAX_BYTES_PER_PROCESS: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);
const COPY_BUFFER: usize = 128 * 1024;

/// A program, as the driver names it: process ID plus the start key that tells apart a reused ID.
pub type ProcessKey = (u32, u64);

#[derive(Debug, Clone)]
struct Entry {
    id: Uuid,
    original: PathBuf,
    sha256: [u8; 32],
    size: u64,
    saved_at: SystemTime,
}

#[derive(Default)]
struct Index {
    by_process: HashMap<ProcessKey, Vec<Entry>>,
    /// Paths already saved or being saved for a program, so each is saved once.
    claimed: HashMap<ProcessKey, HashSet<PathBuf>>,
    process_bytes: HashMap<ProcessKey, u64>,
    total_bytes: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreSummary {
    /// Files put back as they were.
    pub restored: usize,
    /// Files that were already as saved, so nothing was needed.
    pub unchanged: usize,
    /// Files that could not be put back; the saved copy was kept in the vault.
    pub failed: usize,
}

pub struct RollbackVault {
    root: PathBuf,
    index: Mutex<Index>,
}

impl RollbackVault {
    /// Opens the vault at `root`, discarding anything left from a previous run: the programs it
    /// was saved for are gone, and a conviction after a restart has nothing to match.
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        for entry in fs::read_dir(&root)?.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(Self {
            root,
            index: Mutex::new(Index::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn data_path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.bin"))
    }

    /// Saves the current contents of `path` for `process`, once. Returns whether a copy was made;
    /// a file that is missing, too large, unreadable, or over a quota is skipped, never an error
    /// worth delaying the driver for.
    pub fn preserve(&self, process: ProcessKey, path: &Path) -> bool {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return false;
        }
        let size = metadata.len();

        {
            let mut index = self.lock();
            let claimed = index.claimed.entry(process).or_default();
            if claimed.contains(path) || claimed.len() >= MAX_FILES_PER_PROCESS {
                return false;
            }
            let process_bytes = index.process_bytes.get(&process).copied().unwrap_or(0);
            if process_bytes.saturating_add(size) > MAX_BYTES_PER_PROCESS
                || index.total_bytes.saturating_add(size) > MAX_TOTAL_BYTES
            {
                return false;
            }
            index
                .claimed
                .get_mut(&process)
                .expect("inserted above")
                .insert(path.to_path_buf());
            *index.process_bytes.entry(process).or_default() += size;
            index.total_bytes += size;
        }

        let id = Uuid::new_v4();
        match copy_with_digest(path, &self.data_path(id)) {
            Ok((sha256, copied)) => {
                let mut index = self.lock();
                // The file may have changed size between the check and the copy.
                index.total_bytes = index.total_bytes - size + copied;
                if let Some(bytes) = index.process_bytes.get_mut(&process) {
                    *bytes = *bytes - size + copied;
                }
                index.by_process.entry(process).or_default().push(Entry {
                    id,
                    original: path.to_path_buf(),
                    sha256,
                    size: copied,
                    saved_at: SystemTime::now(),
                });
                true
            }
            Err(_) => {
                let _ = fs::remove_file(self.data_path(id));
                let mut index = self.lock();
                if let Some(claimed) = index.claimed.get_mut(&process) {
                    claimed.remove(path);
                }
                if let Some(bytes) = index.process_bytes.get_mut(&process) {
                    *bytes = bytes.saturating_sub(size);
                }
                index.total_bytes = index.total_bytes.saturating_sub(size);
                false
            }
        }
    }

    /// Puts back every file saved for `process`.
    ///
    /// `verify_parent` is called with each file's folder before anything is written there: restore
    /// runs as SYSTEM into folders a standard user controls, so the caller supplies the same
    /// junction check quarantine restore uses. A file whose current contents differ from the saved
    /// ones is kept beside the saved copy in the vault, not destroyed.
    pub fn restore(
        &self,
        process: ProcessKey,
        verify_parent: impl Fn(&Path) -> io::Result<()>,
    ) -> RestoreSummary {
        let entries = {
            let mut index = self.lock();
            index.claimed.remove(&process);
            index.process_bytes.remove(&process);
            let entries = index.by_process.remove(&process).unwrap_or_default();
            for entry in &entries {
                index.total_bytes = index.total_bytes.saturating_sub(entry.size);
            }
            entries
        };

        let mut summary = RestoreSummary::default();
        for entry in entries {
            match self.restore_one(&entry, &verify_parent) {
                Ok(true) => {
                    summary.restored += 1;
                    let _ = fs::remove_file(self.data_path(entry.id));
                }
                Ok(false) => {
                    summary.unchanged += 1;
                    let _ = fs::remove_file(self.data_path(entry.id));
                }
                Err(error) => {
                    log::warn!(
                        "Could not restore {:?} from the rollback vault: {error}",
                        entry.original
                    );
                    summary.failed += 1;
                }
            }
        }
        summary
    }

    fn restore_one(
        &self,
        entry: &Entry,
        verify_parent: &impl Fn(&Path) -> io::Result<()>,
    ) -> io::Result<bool> {
        let parent = entry
            .original
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent folder"))?;
        verify_parent(parent)?;

        let current = match fs::symlink_metadata(&entry.original) {
            Ok(metadata) if metadata.is_file() => Some(digest_of(&entry.original)?),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the original path is no longer a regular file",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if current == Some(entry.sha256) {
            return Ok(false);
        }

        // What is there now is what the program left. Keep it, in case it is not what we think.
        if current.is_some() {
            fs::copy(
                &entry.original,
                self.root.join(format!("{}.replaced", entry.id)),
            )?;
        }

        let saved = self.data_path(entry.id);
        if digest_of(&saved)? != entry.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the saved copy no longer matches its digest",
            ));
        }
        let temporary = parent.join(format!(".blackshard-restore-{}.tmp", entry.id));
        let result = (|| -> io::Result<()> {
            fs::copy(&saved, &temporary)?;
            File::open(&temporary)?.sync_all()?;
            // Replaces the damaged file, or creates the file a program deleted or renamed away.
            fs::rename(&temporary, &entry.original)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        if digest_of(&entry.original)? != entry.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the restored file does not match the saved copy",
            ));
        }
        Ok(true)
    }

    /// Drops what is older than the vault keeps. Called now and then by the service.
    pub fn purge_expired(&self) {
        let now = SystemTime::now();
        let mut expired = Vec::new();
        {
            let mut index = self.lock();
            let mut freed = 0u64;
            for entries in index.by_process.values_mut() {
                entries.retain(|entry| {
                    let old = now
                        .duration_since(entry.saved_at)
                        .is_ok_and(|age| age > MAX_AGE);
                    if old {
                        expired.push(entry.id);
                        freed += entry.size;
                    }
                    !old
                });
            }
            index.by_process.retain(|_, entries| !entries.is_empty());
            index.total_bytes = index.total_bytes.saturating_sub(freed);
            // The claims and per-program byte counts of programs with nothing left go too.
            let live: HashSet<ProcessKey> = index.by_process.keys().copied().collect();
            index.claimed.retain(|process, _| live.contains(process));
            index
                .process_bytes
                .retain(|process, _| live.contains(process));
        }
        for id in expired {
            let _ = fs::remove_file(self.data_path(id));
        }
    }

    #[cfg(test)]
    fn total_bytes(&self) -> u64 {
        self.lock().total_bytes
    }
}

fn copy_with_digest(source: &Path, destination: &Path) -> io::Result<([u8; 32], u64)> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut copied = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        if copied > MAX_FILE_BYTES {
            return Err(io::Error::other(
                "the file grew past the vault's size limit",
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    Ok((hasher.finalize().into(), copied))
}

fn digest_of(path: &Path) -> io::Result<[u8; 32]> {
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

static VAULT: OnceLock<RollbackVault> = OnceLock::new();

/// Opens the service's vault. Until this is called, [`global`] is `None` and nothing is saved.
pub fn init(root: impl Into<PathBuf>) -> io::Result<()> {
    let vault = RollbackVault::new(root)?;
    let _ = VAULT.set(vault);
    Ok(())
}

pub fn global() -> Option<&'static RollbackVault> {
    VAULT.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITER: ProcessKey = (4242, 0xabcdef);
    const OTHER: ProcessKey = (7, 99);

    fn vault() -> (tempfile::TempDir, RollbackVault) {
        let directory = tempfile::tempdir().unwrap();
        let vault = RollbackVault::new(directory.path().join("vault")).unwrap();
        (directory, vault)
    }

    fn allow(_: &Path) -> io::Result<()> {
        Ok(())
    }

    #[test]
    fn encrypted_files_come_back() {
        let (directory, vault) = vault();
        let documents = directory.path().join("Documents");
        fs::create_dir_all(&documents).unwrap();
        let report = documents.join("report.docx");
        fs::write(&report, b"quarterly numbers").unwrap();

        assert!(vault.preserve(WRITER, &report));
        // The program encrypts it in place.
        fs::write(&report, b"\x13\x99 ciphertext \xfe").unwrap();

        let summary = vault.restore(WRITER, allow);
        assert_eq!(
            summary,
            RestoreSummary {
                restored: 1,
                unchanged: 0,
                failed: 0
            }
        );
        assert_eq!(fs::read(&report).unwrap(), b"quarterly numbers");
        // What the program wrote is kept, not destroyed.
        let kept = fs::read_dir(directory.path().join("vault"))
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "replaced")
            })
            .count();
        assert_eq!(kept, 1);
        assert_eq!(vault.total_bytes(), 0);
    }

    #[test]
    fn deleted_and_renamed_files_come_back() {
        let (directory, vault) = vault();
        let photo = directory.path().join("photo.jpg");
        fs::write(&photo, b"jpeg bytes").unwrap();
        assert!(vault.preserve(WRITER, &photo));
        fs::rename(&photo, directory.path().join("photo.jpg.locked")).unwrap();

        assert_eq!(vault.restore(WRITER, allow).restored, 1);
        assert_eq!(fs::read(&photo).unwrap(), b"jpeg bytes");
    }

    #[test]
    fn untouched_files_are_left_alone() {
        let (directory, vault) = vault();
        let note = directory.path().join("note.txt");
        fs::write(&note, b"unchanged").unwrap();
        assert!(vault.preserve(WRITER, &note));
        let summary = vault.restore(WRITER, allow);
        assert_eq!((summary.restored, summary.unchanged), (0, 1));
    }

    #[test]
    fn a_file_is_saved_once_per_program_and_programs_do_not_share() {
        let (directory, vault) = vault();
        let note = directory.path().join("note.txt");
        fs::write(&note, b"first").unwrap();
        assert!(vault.preserve(WRITER, &note));
        // A second write by the same program must not overwrite the original with its own output.
        fs::write(&note, b"already modified").unwrap();
        assert!(!vault.preserve(WRITER, &note));
        assert!(vault.preserve(OTHER, &note));

        vault.restore(WRITER, allow);
        assert_eq!(fs::read(&note).unwrap(), b"first");
    }

    #[test]
    fn limits_are_enforced() {
        let (directory, vault) = vault();
        let big = directory.path().join("big.iso");
        File::create(&big)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        assert!(!vault.preserve(WRITER, &big));
        assert!(!vault.preserve(WRITER, &directory.path().join("missing.txt")));
        assert!(!vault.preserve(WRITER, directory.path()));

        for index in 0..MAX_FILES_PER_PROCESS + 5 {
            let file = directory.path().join(format!("f{index}.txt"));
            fs::write(&file, b"x").unwrap();
            let saved = vault.preserve(WRITER, &file);
            assert_eq!(saved, index < MAX_FILES_PER_PROCESS, "file {index}");
        }
    }

    #[test]
    fn a_refused_folder_stops_the_restore_and_keeps_the_copy() {
        let (directory, vault) = vault();
        let file = directory.path().join("secret.txt");
        fs::write(&file, b"original").unwrap();
        assert!(vault.preserve(WRITER, &file));
        fs::write(&file, b"ciphertext").unwrap();

        let summary = vault.restore(WRITER, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "redirected",
            ))
        });
        assert_eq!(summary.failed, 1);
        assert_eq!(fs::read(&file).unwrap(), b"ciphertext");
        // The saved copy is still there for a person to recover.
        assert!(fs::read_dir(directory.path().join("vault"))
            .unwrap()
            .flatten()
            .any(|entry| entry.path().extension().is_some_and(|ext| ext == "bin")));
    }

    #[test]
    fn a_tampered_copy_is_never_restored() {
        let (directory, vault) = vault();
        let file = directory.path().join("doc.txt");
        fs::write(&file, b"original").unwrap();
        assert!(vault.preserve(WRITER, &file));
        for entry in fs::read_dir(directory.path().join("vault"))
            .unwrap()
            .flatten()
        {
            fs::write(entry.path(), b"swapped").unwrap();
        }
        fs::write(&file, b"ciphertext").unwrap();
        assert_eq!(vault.restore(WRITER, allow).failed, 1);
        assert_eq!(fs::read(&file).unwrap(), b"ciphertext");
    }

    #[test]
    fn opening_the_vault_clears_what_an_earlier_run_left() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("stale.bin"), b"old").unwrap();
        let _vault = RollbackVault::new(&root).unwrap();
        assert!(!root.join("stale.bin").exists());
    }

    #[test]
    fn expired_copies_are_dropped() {
        let (directory, vault) = vault();
        let file = directory.path().join("doc.txt");
        fs::write(&file, b"original").unwrap();
        assert!(vault.preserve(WRITER, &file));
        vault.purge_expired();
        assert_eq!(vault.total_bytes(), 8, "a fresh copy is kept");

        for entries in vault.lock().by_process.values_mut() {
            for entry in entries {
                entry.saved_at = SystemTime::now() - MAX_AGE - Duration::from_secs(1);
            }
        }
        vault.purge_expired();
        assert_eq!(vault.total_bytes(), 0);
        assert_eq!(
            fs::read_dir(directory.path().join("vault"))
                .unwrap()
                .count(),
            0
        );
    }
}
