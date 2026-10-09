use crate::atomic_file;
use crate::detection::opened_file_id;
#[cfg(windows)]
use crate::detection::opened_file_identity;
use chacha20poly1305::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    KeyInit, XChaCha20Poly1305,
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONTAINER_MAGIC: &[u8; 8] = b"BSQ\0\0\0\x01\0";
const CONTAINER_MAGIC_V2: &[u8; 8] = b"BSQ\0\0\0\x02\0";
const COPY_BUFFER_SIZE: usize = 256 * 1024;
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_QUARANTINE_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationState {
    Isolated,

    SourceStillPresent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub id: Uuid,
    pub original_path: PathBuf,
    pub quarantined_at: DateTime<Utc>,
    pub sha256: String,
    pub size: u64,
    pub threat_name: String,
    pub risk_score: u8,
    pub state: IsolationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<[u8; 12]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_secret: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default_for_machine() -> Self {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Self::new(base.join("blackshard").join("Quarantine"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    pub fn quarantine(
        &self,
        source: &Path,
        threat_name: impl Into<String>,
        risk_score: u8,
    ) -> io::Result<QuarantineRecord> {
        let bytes = fs::read(source)?;
        let expected_size = bytes.len() as u64;
        let expected_sha256 = hex::encode(Sha256::digest(&bytes));
        self.quarantine_inner(
            source,
            threat_name.into(),
            risk_score,
            &expected_sha256,
            expected_size,
            None,
        )
    }

    pub fn quarantine_verified(
        &self,
        source: &Path,
        threat_name: impl Into<String>,
        risk_score: u8,
        expected_sha256: &str,
        expected_size: u64,
        expected_file_id: Option<u64>,
    ) -> io::Result<QuarantineRecord> {
        self.quarantine_inner(
            source,
            threat_name.into(),
            risk_score,
            expected_sha256,
            expected_size,
            expected_file_id,
        )
    }

    fn quarantine_inner(
        &self,
        source: &Path,
        threat_name: String,
        risk_score: u8,
        expected_sha256: &str,
        expected_size: u64,
        expected_file_id: Option<u64>,
    ) -> io::Result<QuarantineRecord> {
        self.ensure_root()?;

        if expected_size > MAX_QUARANTINE_SOURCE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the candidate exceeds blackshard's hard quarantine size limit",
            ));
        }
        if expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the expected SHA-256 digest is invalid",
            ));
        }

        let source_metadata = fs::symlink_metadata(source)?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "quarantine only accepts regular files and never follows symlinks",
            ));
        }

        let original_path = fs::canonicalize(source)?;
        let canonical_root = fs::canonicalize(&self.root)?;
        if original_path.starts_with(&canonical_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a quarantine container cannot be quarantined again",
            ));
        }

        let id = Uuid::new_v4();
        let payload_path = self.payload_path(id);
        let temporary_payload = self.root.join(format!(".{id}.payload.tmp"));
        // Key material comes straight from the OS; if it cannot supply any, nothing is written.
        let mut kdf_secret = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut kdf_secret)
            .map_err(io::Error::other)?;

        let hk = Hkdf::<sha2::Sha256>::new(Some(expected_sha256.as_bytes()), &kdf_secret);
        let mut okm = [0u8; 32];
        hk.expand(id.as_bytes(), &mut okm).unwrap();

        let mut stream_nonce = [0u8; 19];
        SysRng
            .try_fill_bytes(&mut stream_nonce)
            .map_err(io::Error::other)?;

        let aad = format!(
            "BSQ|V2|{}|{}|{}|{}",
            original_path.to_string_lossy(),
            threat_name,
            expected_sha256,
            expected_size
        )
        .into_bytes();

        let copy_result = (|| -> io::Result<(String, u64, File)> {
            let input = open_source_for_quarantine(&original_path)?;
            let opened_metadata = input.metadata()?;
            if opened_metadata.file_type().is_symlink() || !opened_metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the source changed into a non-regular file before quarantine",
                ));
            }
            if opened_metadata.len() != expected_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the file size changed after it was scanned; quarantine was aborted",
                ));
            }
            #[cfg(windows)]
            {
                let identity = opened_file_identity(&input)?;
                if identity.link_count > 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "automatic quarantine cannot prove isolation because the file has additional hard links",
                    ));
                }
            }
            if let Some(expected_file_id) = expected_file_id {
                let actual_file_id = opened_file_id(&input)?;
                if actual_file_id != expected_file_id {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the file identity changed after it was scanned; quarantine was aborted",
                    ));
                }
            }
            let output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_payload)?;
            let mut reader = BufReader::with_capacity(COPY_BUFFER_SIZE, input);
            let mut writer = BufWriter::with_capacity(COPY_BUFFER_SIZE, output);
            writer.write_all(CONTAINER_MAGIC_V2)?;
            writer.write_all(&stream_nonce)?;

            let aead = XChaCha20Poly1305::new(&okm.into());
            let mut encryptor = EncryptorBE32::from_aead(aead, &stream_nonce.into());

            let mut hasher = Sha256::new();
            let mut size = 0u64;
            let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
            let mut first_chunk = true;

            if expected_size == 0 {
                let mut chunk_buf = vec![];
                encryptor
                    .encrypt_last_in_place(aad.as_slice(), &mut chunk_buf)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encryption failed"))?;
                writer.write_all(&chunk_buf)?;
            } else {
                loop {
                    if size > expected_size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the file grew while it was being quarantined",
                        ));
                    }
                    let remaining = expected_size - size;
                    if remaining == 0 {
                        break;
                    }
                    let read_limit = (remaining as usize).min(buffer.len());
                    let read = reader.read(&mut buffer[..read_limit])?;
                    if read == 0 {
                        break;
                    }

                    let mut chunk_buf = buffer[..read].to_vec();
                    hasher.update(&chunk_buf);
                    size += read as u64;

                    let chunk_aad = if first_chunk {
                        first_chunk = false;
                        aad.as_slice()
                    } else {
                        &[]
                    };

                    let is_last = size == expected_size;
                    if is_last {
                        encryptor
                            .encrypt_last_in_place(chunk_aad, &mut chunk_buf)
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "encryption failed")
                            })?;
                        writer.write_all(&chunk_buf)?;
                        break;
                    } else {
                        encryptor
                            .encrypt_next_in_place(chunk_aad, &mut chunk_buf)
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "encryption failed")
                            })?;
                        writer.write_all(&chunk_buf)?;
                    }
                }
            }

            if size != expected_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the file size changed while it was being quarantined",
                ));
            }

            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok((hex::encode(hasher.finalize()), size, reader.into_inner()))
        })();

        let (sha256, size, opened_source) = match copy_result {
            Ok(result) => result,
            Err(error) => {
                let _ = fs::remove_file(&temporary_payload);
                return Err(error);
            }
        };

        if !sha256.eq_ignore_ascii_case(expected_sha256) {
            let _ = fs::remove_file(&temporary_payload);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the file changed after it was scanned; quarantine was aborted",
            ));
        }

        if let Err(error) = rename_no_replace(&temporary_payload, &payload_path) {
            let _ = fs::remove_file(&temporary_payload);
            return Err(error);
        }

        let mut record = QuarantineRecord {
            id,
            original_path,
            quarantined_at: Utc::now(),
            sha256,
            size,
            threat_name,
            risk_score,
            state: IsolationState::SourceStillPresent,
            key: None,
            nonce: None,
            kdf_secret: Some(kdf_secret),
        };

        if let Err(error) = self.write_record(&record) {
            let _ = fs::remove_file(&payload_path);
            return Err(error);
        }

        let mut delete_result = delete_open_file(&opened_source, &record.original_path);
        if delete_result.is_err() && stop_running_copies(&record.original_path) {
            // The image section goes away shortly after its last process exits.
            for _ in 0..10 {
                delete_result = delete_open_file(&opened_source, &record.original_path);
                if delete_result.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        drop(opened_source);
        if delete_result.is_ok() && !record.original_path.exists() {
            record.state = IsolationState::Isolated;
            self.write_record(&record)?;
        }

        Ok(record)
    }

    pub fn list(&self) -> io::Result<Vec<QuarantineRecord>> {
        self.ensure_root()?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }

            match read_record_file(&path) {
                Ok(mut record)
                    if path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .and_then(|value| Uuid::parse_str(value).ok())
                        == Some(record.id) =>
                {
                    self.reconcile_state(&mut record);
                    records.push(record)
                }
                Err(error) => {
                    eprintln!("blackshard ignored corrupt quarantine metadata {path:?}: {error}");
                }
                Ok(_) => {
                    eprintln!("blackshard ignored mismatched quarantine metadata {path:?}");
                }
            }
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.quarantined_at));
        Ok(records)
    }

    pub fn load(&self, id: Uuid) -> io::Result<QuarantineRecord> {
        let mut record = read_record_file(&self.metadata_path(id))?;
        if record.id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quarantine metadata identifier does not match its file name",
            ));
        }
        self.reconcile_state(&mut record);
        Ok(record)
    }

    pub fn restore(
        &self,
        id: Uuid,
        destination: Option<&Path>,
        remove_after_restore: bool,
    ) -> io::Result<PathBuf> {
        let record = self.load(id)?;
        let destination = destination
            .map(Path::to_path_buf)
            .unwrap_or_else(|| record.original_path.clone());

        if destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("restore target already exists: {}", destination.display()),
            ));
        }

        let parent = destination.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "restore target has no parent")
        })?;
        fs::create_dir_all(parent)?;

        let temporary_name = destination
            .file_name()
            .map(OsString::from)
            .unwrap_or_else(|| OsString::from("restored"));
        let mut temporary_name_with_suffix = temporary_name;
        temporary_name_with_suffix.push(format!(".blackshard-{id}.tmp"));
        let temporary_path = parent.join(temporary_name_with_suffix);

        let restore_result = (|| -> io::Result<String> {
            let input = File::open(self.payload_path(id))?;
            let output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path)?;
            let mut reader = BufReader::with_capacity(COPY_BUFFER_SIZE, input);
            let mut writer = BufWriter::with_capacity(COPY_BUFFER_SIZE, output);

            let mut magic = [0u8; 8];
            reader.read_exact(&mut magic)?;

            if &magic == CONTAINER_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "legacy unauthenticated quarantine containers are no longer supported for restore",
                ));
            } else if &magic != CONTAINER_MAGIC_V2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid blackshard quarantine container",
                ));
            }

            let kdf_secret = record.kdf_secret.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing KDF secret in metadata")
            })?;

            let hk = Hkdf::<sha2::Sha256>::new(Some(record.sha256.as_bytes()), &kdf_secret);
            let mut okm = [0u8; 32];
            hk.expand(id.as_bytes(), &mut okm).unwrap();

            let mut stream_nonce = [0u8; 19];
            reader.read_exact(&mut stream_nonce)?;

            let aead = XChaCha20Poly1305::new(&okm.into());
            let mut decryptor = DecryptorBE32::from_aead(aead, &stream_nonce.into());

            let mut hasher = Sha256::new();
            let mut restored_size = 0u64;

            let aad = format!(
                "BSQ|V2|{}|{}|{}|{}",
                record.original_path.to_string_lossy(),
                record.threat_name,
                record.sha256,
                record.size
            )
            .into_bytes();
            let mut first_chunk = true;

            if record.size == 0 {
                let mut chunk_buf = vec![];
                let mut mac_buf = [0u8; 16];
                reader.read_exact(&mut mac_buf)?;
                chunk_buf.extend_from_slice(&mac_buf);

                decryptor
                    .decrypt_last_in_place(aad.as_slice(), &mut chunk_buf)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "container integrity check failed",
                        )
                    })?;
                writer.write_all(&chunk_buf)?;
            } else {
                loop {
                    if restored_size > record.size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "quarantine container exceeds its recorded size",
                        ));
                    }
                    let remaining_plaintext = record.size - restored_size;
                    if remaining_plaintext == 0 {
                        break;
                    }
                    let chunk_plaintext_limit =
                        (remaining_plaintext as usize).min(COPY_BUFFER_SIZE);
                    let read_limit = chunk_plaintext_limit + 16;

                    let mut chunk_buf = vec![0u8; read_limit];
                    reader.read_exact(&mut chunk_buf)?;

                    let chunk_aad = if first_chunk {
                        first_chunk = false;
                        aad.as_slice()
                    } else {
                        &[]
                    };

                    let is_last = restored_size + (chunk_plaintext_limit as u64) == record.size;

                    if is_last {
                        decryptor
                            .decrypt_last_in_place(chunk_aad, &mut chunk_buf)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "container integrity check failed",
                                )
                            })?;
                        hasher.update(&chunk_buf);
                        writer.write_all(&chunk_buf)?;
                        restored_size += chunk_buf.len() as u64;
                        break;
                    } else {
                        decryptor
                            .decrypt_next_in_place(chunk_aad, &mut chunk_buf)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "container integrity check failed",
                                )
                            })?;
                        hasher.update(&chunk_buf);
                        writer.write_all(&chunk_buf)?;
                        restored_size += chunk_buf.len() as u64;
                    }
                }
            }
            if restored_size != record.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "quarantine container size does not match its metadata",
                ));
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok(hex::encode(hasher.finalize()))
        })();

        let restored_hash = match restore_result {
            Ok(hash) => hash,
            Err(error) => {
                let _ = fs::remove_file(&temporary_path);
                return Err(error);
            }
        };

        if !restored_hash.eq_ignore_ascii_case(&record.sha256) {
            let _ = fs::remove_file(&temporary_path);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quarantine integrity check failed; nothing was restored",
            ));
        }

        rename_no_replace(&temporary_path, &destination)?;
        if remove_after_restore {
            self.delete(id)?;
        }
        Ok(destination)
    }

    pub fn delete(&self, id: Uuid) -> io::Result<()> {
        let payload = self.payload_path(id);
        let metadata = self.metadata_path(id);
        let mut first_error = None;

        for path in [payload, metadata] {
            if let Err(error) = fs::remove_file(&path) {
                if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn ensure_root(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)
    }

    fn payload_path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.payload"))
    }

    fn metadata_path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    fn write_record(&self, record: &QuarantineRecord) -> io::Result<()> {
        let final_path = self.metadata_path(record.id);
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        atomic_file::write(&final_path, &bytes)
    }

    fn reconcile_state(&self, record: &mut QuarantineRecord) {
        if record.state == IsolationState::SourceStillPresent && !record.original_path.exists() {
            record.state = IsolationState::Isolated;
            let _ = self.write_record(record);
        }
    }
}

#[cfg(windows)]
fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

#[cfg(windows)]
fn open_source_for_quarantine(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_source_for_quarantine(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn delete_open_file(file: &File, _original_path: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileInformationByHandle(
            file: isize,
            information_class: i32,
            information: *const c_void,
            buffer_size: u32,
        ) -> i32;
    }

    const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
    let disposition = FileDispositionInfo { delete_file: 1 };
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as isize,
            FILE_DISPOSITION_INFO_CLASS,
            (&disposition as *const FileDispositionInfo).cast(),
            std::mem::size_of::<FileDispositionInfo>() as u32,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Stops every process running the convicted file, since Windows will not delete a mapped image.
/// Returns whether any was stopped.
#[cfg(windows)]
fn stop_running_copies(path: &Path) -> bool {
    let stopped = crate::realtime::terminate_processes_running(path);
    if stopped > 0 {
        log::warn!("Stopped {stopped} process(es) running {path:?} so it could be quarantined");
    }
    stopped > 0
}

#[cfg(not(windows))]
fn stop_running_copies(_path: &Path) -> bool {
    false
}

#[cfg(not(windows))]
fn delete_open_file(_file: &File, original_path: &Path) -> io::Result<()> {
    fs::remove_file(original_path)
}

fn read_record_file(path: &Path) -> io::Result<QuarantineRecord> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine metadata is not a regular, non-symlink file",
        ));
    }
    if metadata.len() > MAX_METADATA_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine metadata exceeds its size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine metadata exceeds its size limit",
        ));
    }
    decode_json(&bytes)
}

fn decode_json(bytes: &[u8]) -> io::Result<QuarantineRecord> {
    serde_json::from_slice(bytes).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_round_trip_neutralizes_and_restores() {
        let temporary = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(temporary.path().join("vault"));
        let source = temporary.path().join("sample.exe");
        let original = b"MZ harmless unit-test payload".repeat(4096);
        fs::write(&source, &original).unwrap();

        let record = store
            .quarantine(&source, "Unit.Test.Detection", 100)
            .unwrap();
        assert_eq!(record.state, IsolationState::Isolated);
        assert!(!source.exists());

        let payload = fs::read(store.payload_path(record.id)).unwrap();
        assert!(payload.starts_with(CONTAINER_MAGIC_V2));
        assert_ne!(&payload[CONTAINER_MAGIC_V2.len()..], original.as_slice());

        let restored = store.restore(record.id, Some(&source), false).unwrap();
        assert_eq!(restored, source);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn restore_never_overwrites_an_existing_file() {
        let temporary = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(temporary.path().join("vault"));
        let source = temporary.path().join("sample.bin");
        fs::write(&source, b"original").unwrap();
        let record = store.quarantine(&source, "Unit.Test", 100).unwrap();
        fs::write(&source, b"replacement").unwrap();

        let error = store.restore(record.id, None, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&source).unwrap(), b"replacement");
    }

    #[test]
    fn corrupt_container_is_not_restored() {
        let temporary = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(temporary.path().join("vault"));
        let source = temporary.path().join("sample.bin");
        fs::write(&source, b"original").unwrap();
        let record = store.quarantine(&source, "Unit.Test", 100).unwrap();
        fs::write(store.payload_path(record.id), b"corrupt").unwrap();

        assert!(store.restore(record.id, None, false).is_err());
        assert!(!source.exists());
    }

    #[test]
    fn verified_quarantine_rejects_a_replaced_file() {
        let temporary = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(temporary.path().join("vault"));
        let source = temporary.path().join("sample.bin");
        fs::write(&source, b"replacement").unwrap();

        let error = store
            .quarantine_verified(&source, "Unit.Test", 100, &"00".repeat(32), 11, None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(source.exists());
        assert!(store.list().unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn a_running_program_is_stopped_so_it_can_be_quarantined() {
        let temporary = tempfile::tempdir().unwrap();
        let store = QuarantineStore::new(temporary.path().join("vault"));
        let program = temporary.path().join("running-sample.exe");
        let system_root = std::env::var_os("SystemRoot").unwrap();
        fs::copy(Path::new(&system_root).join(r"System32\PING.EXE"), &program).unwrap();
        let mut child = std::process::Command::new(&program)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));

        let record = store
            .quarantine(&program, "Unit.Test.Running", 100)
            .unwrap();
        assert_eq!(record.state, IsolationState::Isolated);
        assert!(!program.exists());
        assert!(
            child.try_wait().unwrap().is_some(),
            "the running copy was not stopped"
        );
    }
}
