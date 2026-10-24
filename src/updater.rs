use crate::atomic_file;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use url::Url;

pub const UPDATE_SCHEMA_VERSION: u32 = 2;
pub const UPDATE_PRODUCT_ID: &str = "blackshard";
pub const UPDATE_CHANNEL: &str = "stable";

pub const MAX_UPDATE_SEQUENCE: u64 = u64::MAX - 1;

pub const MAX_UPDATE_EXPIRY_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_UPDATE_CLOCK_SKEW: Duration = Duration::from_secs(15 * 60);
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
pub const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(4 * 60 * 60);
pub const UPDATE_CHECK_JITTER: Duration = Duration::from_secs(15 * 60);

const SIGNING_DOMAIN: &[u8] = b"BLACKSHARD-UPDATE-MANIFEST-V2\0";

const ACTIVATION_POINTER_SCHEMA_VERSION: u32 = 1;
const PAYLOAD_FILE_NAME: &str = "rules.bundle";
const ENVELOPE_FILE_NAME: &str = "envelope.json";
const CURRENT_POINTER_FILE: &str = "current.json";
const PREVIOUS_POINTER_FILE: &str = "previous.json";
const COPY_BUFFER_BYTES: usize = 256 * 1024;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub product: String,
    pub channel: String,
    pub sequence: u64,
    pub version: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub payload_url: String,
    pub payload_size: u64,
    pub payload_sha256: String,
}

impl UpdateManifest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        let digest = decode_hex_exact::<32>(&self.payload_sha256)
            .map_err(|_| UpdateError::MalformedManifest("payload_sha256 must be 64 hex digits"))?;

        let mut bytes = Vec::with_capacity(
            SIGNING_DOMAIN.len()
                + self.product.len()
                + self.channel.len()
                + self.version.len()
                + self.payload_url.len()
                + 116,
        );
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        append_length_prefixed(&mut bytes, self.product.as_bytes())?;
        append_length_prefixed(&mut bytes, self.channel.as_bytes())?;
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.issued_at.timestamp().to_be_bytes());
        bytes.extend_from_slice(&self.issued_at.timestamp_subsec_nanos().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.timestamp().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.timestamp_subsec_nanos().to_be_bytes());
        bytes.extend_from_slice(&self.payload_size.to_be_bytes());
        append_length_prefixed(&mut bytes, self.version.as_bytes())?;
        append_length_prefixed(&mut bytes, self.payload_url.as_bytes())?;
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdateEnvelope {
    pub manifest: UpdateManifest,
    pub signature_ed25519: String,
}

impl SignedUpdateEnvelope {
    pub fn from_json(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(UpdateError::EnvelopeTooLarge {
                actual: bytes.len(),
                maximum: MAX_ENVELOPE_BYTES,
            });
        }
        serde_json::from_slice(bytes).map_err(|error| UpdateError::Serialization(error.to_string()))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, UpdateError> {
        serde_json::to_vec_pretty(self)
            .map_err(|error| UpdateError::Serialization(error.to_string()))
    }
}

#[derive(Debug)]
pub enum UpdateError {
    UnsupportedSchema {
        found: u32,
    },
    WrongProduct {
        found: String,
    },
    WrongChannel {
        found: String,
    },
    MalformedManifest(&'static str),
    NonHttpsUrl,
    InvalidSignatureEncoding,
    InvalidPublicKey,
    InvalidSignature,
    IssuedInFuture {
        issued_at: DateTime<Utc>,
        latest_allowed: DateTime<Utc>,
    },
    Expired {
        expired_at: DateTime<Utc>,
    },
    ExpiryTooFar {
        expires_at: DateTime<Utc>,
        latest_allowed: DateTime<Utc>,
    },
    SequenceOutOfRange {
        found: u64,
        maximum: u64,
    },
    Rollback {
        offered: u64,
        installed: u64,
    },
    SequenceConflict {
        sequence: u64,
    },
    Oversized {
        declared: u64,
        maximum: u64,
    },
    SizeMismatch {
        declared: u64,
        actual: u64,
    },
    HashMismatch,
    EnvelopeTooLarge {
        actual: usize,
        maximum: usize,
    },
    StateCorrupt(String),
    StorageConflict(PathBuf),
    Serialization(String),
    Io(io::Error),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { found } => {
                write!(formatter, "unsupported update schema version {found}")
            }
            Self::WrongProduct { found } => write!(
                formatter,
                "update targets product {found:?}, expected {UPDATE_PRODUCT_ID:?}"
            ),
            Self::WrongChannel { found } => write!(
                formatter,
                "update targets channel {found:?}, expected {UPDATE_CHANNEL:?}"
            ),
            Self::MalformedManifest(reason) => {
                write!(formatter, "malformed update manifest: {reason}")
            }
            Self::NonHttpsUrl => write!(formatter, "update payload URL is not a safe HTTPS URL"),
            Self::InvalidSignatureEncoding => {
                write!(formatter, "Ed25519 signature must be 128 hex digits")
            }
            Self::InvalidPublicKey => write!(formatter, "invalid Ed25519 public key"),
            Self::InvalidSignature => write!(formatter, "update manifest signature is invalid"),
            Self::IssuedInFuture {
                issued_at,
                latest_allowed,
            } => write!(
                formatter,
                "update issuance {issued_at} exceeds the clock-skew limit {latest_allowed}"
            ),
            Self::Expired { expired_at } => write!(formatter, "update expired at {expired_at}"),
            Self::ExpiryTooFar {
                expires_at,
                latest_allowed,
            } => write!(
                formatter,
                "update expiry {expires_at} exceeds the maximum allowed expiry {latest_allowed}"
            ),
            Self::SequenceOutOfRange { found, maximum } => write!(
                formatter,
                "update sequence {found} exceeds the supported maximum {maximum}"
            ),
            Self::Rollback { offered, installed } => write!(
                formatter,
                "update sequence {offered} does not advance installed sequence {installed}"
            ),
            Self::SequenceConflict { sequence } => write!(
                formatter,
                "update sequence {sequence} was reused with different signed metadata"
            ),
            Self::Oversized { declared, maximum } => write!(
                formatter,
                "update declares {declared} bytes, exceeding the {maximum}-byte limit"
            ),
            Self::SizeMismatch { declared, actual } => write!(
                formatter,
                "update size mismatch: manifest declares {declared} bytes, received {actual}"
            ),
            Self::HashMismatch => write!(
                formatter,
                "update payload SHA-256 does not match the manifest"
            ),
            Self::EnvelopeTooLarge { actual, maximum } => write!(
                formatter,
                "update envelope is {actual} bytes, exceeding the {maximum}-byte limit"
            ),
            Self::StateCorrupt(reason) => write!(formatter, "update state is corrupt: {reason}"),
            Self::StorageConflict(path) => {
                write!(
                    formatter,
                    "existing update storage conflicts at {}",
                    path.display()
                )
            }
            Self::Serialization(reason) => {
                write!(formatter, "update serialization failed: {reason}")
            }
            Self::Io(error) => write!(formatter, "update storage failed: {error}"),
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    pub manifest: UpdateManifest,
    pub payload_sha256: [u8; 32],
}

pub fn verify_manifest(
    envelope: &SignedUpdateEnvelope,
    now: DateTime<Utc>,
    maximum_payload_bytes: u64,
    trusted_public_key: &[u8; 32],
) -> Result<(), UpdateError> {
    validate_manifest_shape(&envelope.manifest)?;

    let signature_bytes = decode_hex_exact::<64>(&envelope.signature_ed25519)
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let public_key =
        VerifyingKey::from_bytes(trusted_public_key).map_err(|_| UpdateError::InvalidPublicKey)?;
    let signed_bytes = envelope.manifest.signing_bytes()?;
    public_key
        .verify_strict(&signed_bytes, &signature)
        .map_err(|_| UpdateError::InvalidSignature)?;

    let clock_skew = chrono::Duration::from_std(MAX_UPDATE_CLOCK_SKEW)
        .map_err(|_| UpdateError::MalformedManifest("clock-skew limit is invalid"))?;
    let latest_issuance =
        now.checked_add_signed(clock_skew)
            .ok_or(UpdateError::MalformedManifest(
                "issuance is outside the supported time range",
            ))?;
    if envelope.manifest.issued_at > latest_issuance {
        return Err(UpdateError::IssuedInFuture {
            issued_at: envelope.manifest.issued_at,
            latest_allowed: latest_issuance,
        });
    }
    if envelope.manifest.expires_at <= now {
        return Err(UpdateError::Expired {
            expired_at: envelope.manifest.expires_at,
        });
    }
    let horizon = chrono::Duration::from_std(MAX_UPDATE_EXPIRY_HORIZON)
        .map_err(|_| UpdateError::MalformedManifest("expiry horizon is invalid"))?;
    let latest_allowed = envelope
        .manifest
        .issued_at
        .checked_add_signed(horizon)
        .ok_or(UpdateError::MalformedManifest(
            "expiry is outside the supported time range",
        ))?;
    if envelope.manifest.expires_at > latest_allowed {
        return Err(UpdateError::ExpiryTooFar {
            expires_at: envelope.manifest.expires_at,
            latest_allowed,
        });
    }
    if envelope.manifest.payload_size > maximum_payload_bytes {
        return Err(UpdateError::Oversized {
            declared: envelope.manifest.payload_size,
            maximum: maximum_payload_bytes,
        });
    }
    Ok(())
}

pub fn verify_update(
    envelope: &SignedUpdateEnvelope,
    payload: &[u8],
    installed_sequence: u64,
    now: DateTime<Utc>,
    maximum_payload_bytes: u64,
    trusted_public_key: &[u8; 32],
) -> Result<VerifiedUpdate, UpdateError> {
    verify_manifest(envelope, now, maximum_payload_bytes, trusted_public_key)?;
    if envelope.manifest.sequence <= installed_sequence {
        return Err(UpdateError::Rollback {
            offered: envelope.manifest.sequence,
            installed: installed_sequence,
        });
    }
    let actual_size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if actual_size != envelope.manifest.payload_size {
        return Err(UpdateError::SizeMismatch {
            declared: envelope.manifest.payload_size,
            actual: actual_size,
        });
    }

    let expected_digest = decode_hex_exact::<32>(&envelope.manifest.payload_sha256)
        .map_err(|_| UpdateError::MalformedManifest("payload_sha256 must be 64 hex digits"))?;
    let actual_digest: [u8; 32] = Sha256::digest(payload).into();
    if actual_digest != expected_digest {
        return Err(UpdateError::HashMismatch);
    }

    Ok(VerifiedUpdate {
        manifest: envelope.manifest.clone(),
        payload_sha256: actual_digest,
    })
}

fn validate_manifest_shape(manifest: &UpdateManifest) -> Result<(), UpdateError> {
    if manifest.schema_version != UPDATE_SCHEMA_VERSION {
        return Err(UpdateError::UnsupportedSchema {
            found: manifest.schema_version,
        });
    }
    if manifest.product != UPDATE_PRODUCT_ID {
        return Err(UpdateError::WrongProduct {
            found: manifest.product.clone(),
        });
    }
    if manifest.channel != UPDATE_CHANNEL {
        return Err(UpdateError::WrongChannel {
            found: manifest.channel.clone(),
        });
    }
    if manifest.sequence == 0 {
        return Err(UpdateError::MalformedManifest(
            "sequence must be greater than zero",
        ));
    }
    if manifest.sequence > MAX_UPDATE_SEQUENCE {
        return Err(UpdateError::SequenceOutOfRange {
            found: manifest.sequence,
            maximum: MAX_UPDATE_SEQUENCE,
        });
    }
    if manifest.version.trim().is_empty() || manifest.version.len() > 128 {
        return Err(UpdateError::MalformedManifest(
            "version must contain 1 through 128 bytes",
        ));
    }
    if manifest.expires_at <= manifest.issued_at {
        return Err(UpdateError::MalformedManifest(
            "expires_at must be later than issued_at",
        ));
    }
    if manifest.payload_size == 0 {
        return Err(UpdateError::MalformedManifest(
            "payload_size must be greater than zero",
        ));
    }
    if manifest.payload_url.len() > 2_048 {
        return Err(UpdateError::MalformedManifest("payload_url is too long"));
    }

    let url = Url::parse(&manifest.payload_url).map_err(|_| UpdateError::NonHttpsUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(UpdateError::NonHttpsUrl);
    }

    decode_hex_exact::<32>(&manifest.payload_sha256)
        .map_err(|_| UpdateError::MalformedManifest("payload_sha256 must be 64 hex digits"))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct UpdateStore {
    root: PathBuf,
    maximum_payload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveUpdate {
    pub sequence: u64,
    pub version: String,
    pub expires_at: DateTime<Utc>,
    pub payload_sha256: String,
    pub payload_path: PathBuf,
    pub envelope_path: PathBuf,
}

impl ActiveUpdate {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivationPointer {
    schema_version: u32,
    sequence: u64,
    version: String,
    expires_at: DateTime<Utc>,
    payload_sha256: String,
}

impl UpdateStore {
    pub fn new(root: impl Into<PathBuf>, maximum_payload_bytes: u64) -> Result<Self, UpdateError> {
        if maximum_payload_bytes == 0 {
            return Err(UpdateError::MalformedManifest(
                "maximum payload size must be greater than zero",
            ));
        }
        Ok(Self {
            root: root.into(),
            maximum_payload_bytes,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn installed_sequence(&self) -> Result<u64, UpdateError> {
        Ok(self
            .read_pointer(&self.state_dir().join(CURRENT_POINTER_FILE))?
            .map_or(0, |pointer| pointer.sequence))
    }

    pub fn current(&self) -> Result<Option<ActiveUpdate>, UpdateError> {
        self.read_active_pointer(&self.state_dir().join(CURRENT_POINTER_FILE))
    }

    pub fn last_known_good(&self) -> Result<Option<ActiveUpdate>, UpdateError> {
        self.read_active_pointer(&self.state_dir().join(PREVIOUS_POINTER_FILE))
    }

    pub fn stage_and_activate(
        &self,
        envelope: &SignedUpdateEnvelope,
        payload: &[u8],
        now: DateTime<Utc>,
        trusted_public_key: &[u8; 32],
    ) -> Result<ActiveUpdate, UpdateError> {
        self.ensure_layout()?;
        let lock_path = self.root.join("update.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.lock()?;

        let installed_sequence = self.installed_sequence()?;
        let verified = verify_update(
            envelope,
            payload,
            installed_sequence,
            now,
            self.maximum_payload_bytes,
            trusted_public_key,
        )?;

        let envelope_json = envelope.to_json()?;
        let directory_name = version_directory_name(
            verified.manifest.sequence,
            &verified.manifest.payload_sha256,
        );
        let final_directory = self.versions_dir().join(&directory_name);
        self.commit_immutable_version(
            &final_directory,
            envelope,
            &envelope_json,
            payload,
            &verified.payload_sha256,
        )?;

        let pointer = ActivationPointer {
            schema_version: ACTIVATION_POINTER_SCHEMA_VERSION,
            sequence: verified.manifest.sequence,
            version: verified.manifest.version,
            expires_at: verified.manifest.expires_at,
            payload_sha256: verified.manifest.payload_sha256.to_ascii_lowercase(),
        };
        let pointer_json = serde_json::to_vec_pretty(&pointer)
            .map_err(|error| UpdateError::Serialization(error.to_string()))?;

        let current_path = self.state_dir().join(CURRENT_POINTER_FILE);
        if let Some(current_bytes) = read_optional_bounded(&current_path, MAX_ENVELOPE_BYTES)? {
            parse_pointer(&current_bytes)?;
            atomic_write(
                &self.state_dir().join(PREVIOUS_POINTER_FILE),
                &current_bytes,
            )?;
        }
        atomic_write(&current_path, &pointer_json)?;

        Ok(self.active_from_pointer(pointer))
    }

    fn ensure_layout(&self) -> Result<(), UpdateError> {
        ensure_real_directory(&self.root)?;
        ensure_real_directory(&self.versions_dir())?;
        ensure_real_directory(&self.state_dir())?;
        Ok(())
    }

    fn versions_dir(&self) -> PathBuf {
        self.root.join("versions")
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    fn read_pointer(&self, path: &Path) -> Result<Option<ActivationPointer>, UpdateError> {
        let Some(bytes) = read_optional_bounded(path, MAX_ENVELOPE_BYTES)? else {
            return Ok(None);
        };
        parse_pointer(&bytes).map(Some)
    }

    fn read_active_pointer(&self, path: &Path) -> Result<Option<ActiveUpdate>, UpdateError> {
        Ok(self
            .read_pointer(path)?
            .map(|pointer| self.active_from_pointer(pointer)))
    }

    fn active_from_pointer(&self, pointer: ActivationPointer) -> ActiveUpdate {
        let directory = self.versions_dir().join(version_directory_name(
            pointer.sequence,
            &pointer.payload_sha256,
        ));
        ActiveUpdate {
            sequence: pointer.sequence,
            version: pointer.version,
            expires_at: pointer.expires_at,
            payload_sha256: pointer.payload_sha256,
            payload_path: directory.join(PAYLOAD_FILE_NAME),
            envelope_path: directory.join(ENVELOPE_FILE_NAME),
        }
    }

    fn commit_immutable_version(
        &self,
        final_directory: &Path,
        envelope: &SignedUpdateEnvelope,
        envelope_json: &[u8],
        payload: &[u8],
        expected_digest: &[u8; 32],
    ) -> Result<(), UpdateError> {
        if final_directory.exists() {
            return validate_existing_version(
                final_directory,
                envelope,
                payload.len() as u64,
                expected_digest,
            );
        }

        let stage_directory = unique_sibling_path(&self.versions_dir(), ".stage");
        fs::create_dir(&stage_directory)?;
        let mut guard = DirectoryCleanupGuard::new(stage_directory.clone());
        create_and_sync(&stage_directory.join(PAYLOAD_FILE_NAME), payload)?;
        create_and_sync(&stage_directory.join(ENVELOPE_FILE_NAME), envelope_json)?;

        match fs::rename(&stage_directory, final_directory) {
            Ok(()) => guard.disarm(),
            Err(_error) if final_directory.exists() => {
                validate_existing_version(
                    final_directory,
                    envelope,
                    payload.len() as u64,
                    expected_digest,
                )?;
            }
            Err(error) => return Err(UpdateError::Io(error)),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateScheduler {
    pub interval: Duration,
    pub maximum_jitter: Duration,
}

impl Default for UpdateScheduler {
    fn default() -> Self {
        Self {
            interval: UPDATE_CHECK_INTERVAL,
            maximum_jitter: UPDATE_CHECK_JITTER,
        }
    }
}

impl UpdateScheduler {
    pub fn delay_for_sample(&self, random_sample: u64) -> Duration {
        let interval_seconds = self.interval.as_secs();
        let maximum_jitter = self
            .maximum_jitter
            .as_secs()
            .min(interval_seconds.saturating_sub(1));
        let span = maximum_jitter.saturating_mul(2).saturating_add(1);
        let selected = if span == 0 { 0 } else { random_sample % span };
        Duration::from_secs(
            interval_seconds
                .saturating_sub(maximum_jitter)
                .saturating_add(selected),
        )
    }

    pub fn next_check(&self, now: SystemTime, random_sample: u64) -> SystemTime {
        now.checked_add(self.delay_for_sample(random_sample))
            .unwrap_or_else(|| SystemTime::UNIX_EPOCH + Duration::from_secs(u64::MAX))
    }
}

fn append_length_prefixed(destination: &mut Vec<u8>, value: &[u8]) -> Result<(), UpdateError> {
    let length = u32::try_from(value.len())
        .map_err(|_| UpdateError::MalformedManifest("manifest string is too long"))?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

fn decode_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], ()> {
    if input.len() != N * 2 {
        return Err(());
    }
    let mut output = [0_u8; N];
    let bytes = input.as_bytes();
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2]).ok_or(())?;
        let low = hex_nibble(bytes[index * 2 + 1]).ok_or(())?;
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn version_directory_name(sequence: u64, digest_hex: &str) -> String {
    format!("{sequence:020}-{}", digest_hex.to_ascii_lowercase())
}

fn ensure_real_directory(path: &Path) -> Result<(), UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(UpdateError::StorageConflict(path.to_path_buf()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(UpdateError::StorageConflict(path.to_path_buf()));
            }
        }
        Err(error) => return Err(UpdateError::Io(error)),
    }
    Ok(())
}

fn create_and_sync(path: &Path, contents: &[u8]) -> Result<(), UpdateError> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_write(destination: &Path, contents: &[u8]) -> Result<(), UpdateError> {
    let parent = destination.parent().ok_or(UpdateError::MalformedManifest(
        "activation path has no parent",
    ))?;
    let temporary = unique_sibling_path(parent, ".pointer");
    let mut guard = FileCleanupGuard::new(temporary.clone());
    create_and_sync(&temporary, contents)?;
    atomic_file::replace(&temporary, destination)?;
    guard.disarm();
    Ok(())
}

fn unique_sibling_path(parent: &Path, prefix: &str) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!("{prefix}-{}-{counter}", std::process::id()))
}

fn read_optional_bounded(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(UpdateError::StorageConflict(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(UpdateError::Io(error)),
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(UpdateError::Io(error)),
    };
    let metadata_length = file.metadata()?.len();
    if metadata_length > maximum as u64 {
        return Err(UpdateError::StateCorrupt(format!(
            "{} exceeds its size limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata_length as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(UpdateError::StateCorrupt(format!(
            "{} exceeds its size limit",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn parse_pointer(bytes: &[u8]) -> Result<ActivationPointer, UpdateError> {
    let pointer: ActivationPointer = serde_json::from_slice(bytes)
        .map_err(|error| UpdateError::StateCorrupt(error.to_string()))?;
    if pointer.schema_version != ACTIVATION_POINTER_SCHEMA_VERSION
        || pointer.sequence == 0
        || pointer.sequence > MAX_UPDATE_SEQUENCE
    {
        return Err(UpdateError::StateCorrupt(
            "invalid activation pointer version or sequence".to_owned(),
        ));
    }
    decode_hex_exact::<32>(&pointer.payload_sha256)
        .map_err(|_| UpdateError::StateCorrupt("invalid pointer digest".to_owned()))?;
    Ok(pointer)
}

fn validate_existing_version(
    directory: &Path,
    expected_envelope: &SignedUpdateEnvelope,
    expected_size: u64,
    expected_digest: &[u8; 32],
) -> Result<(), UpdateError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| UpdateError::StorageConflict(directory.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(UpdateError::StorageConflict(directory.to_path_buf()));
    }
    let envelope_bytes =
        read_optional_bounded(&directory.join(ENVELOPE_FILE_NAME), MAX_ENVELOPE_BYTES)?
            .ok_or_else(|| UpdateError::StorageConflict(directory.to_path_buf()))?;
    let stored_envelope = SignedUpdateEnvelope::from_json(&envelope_bytes)
        .map_err(|_| UpdateError::StorageConflict(directory.to_path_buf()))?;
    if &stored_envelope != expected_envelope {
        return Err(UpdateError::StorageConflict(directory.to_path_buf()));
    }

    let payload_path = directory.join(PAYLOAD_FILE_NAME);
    let mut payload = File::open(&payload_path)
        .map_err(|_| UpdateError::StorageConflict(directory.to_path_buf()))?;
    if payload.metadata()?.len() != expected_size {
        return Err(UpdateError::StorageConflict(directory.to_path_buf()));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = payload.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual_digest: [u8; 32] = hasher.finalize().into();
    if &actual_digest != expected_digest {
        return Err(UpdateError::StorageConflict(directory.to_path_buf()));
    }
    Ok(())
}

struct FileCleanupGuard {
    path: PathBuf,
    armed: bool,
}

impl FileCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FileCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct DirectoryCleanupGuard {
    path: PathBuf,
    armed: bool,
}

impl DirectoryCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DirectoryCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "blackshard-updater-test-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).single().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(ALPHABET[(byte >> 4) as usize] as char);
            result.push(ALPHABET[(byte & 0x0f) as usize] as char);
        }
        result
    }

    fn signed_envelope(sequence: u64, payload: &[u8]) -> SignedUpdateEnvelope {
        let key = signing_key();
        let manifest = UpdateManifest {
            schema_version: UPDATE_SCHEMA_VERSION,
            product: UPDATE_PRODUCT_ID.to_owned(),
            channel: UPDATE_CHANNEL.to_owned(),
            sequence,
            version: format!("2027.1.{sequence}"),
            issued_at: now(),
            expires_at: now() + chrono::Duration::days(2),
            payload_url: format!("https://updates.blackshard.dev/rules/{sequence}.bundle"),
            payload_size: payload.len() as u64,
            payload_sha256: hex(&Sha256::digest(payload)),
        };
        let signature = key.sign(&manifest.signing_bytes().unwrap());
        SignedUpdateEnvelope {
            manifest,
            signature_ed25519: hex(&signature.to_bytes()),
        }
    }

    fn verify(
        envelope: &SignedUpdateEnvelope,
        payload: &[u8],
        installed: u64,
        max: u64,
    ) -> Result<VerifiedUpdate, UpdateError> {
        verify_update(
            envelope,
            payload,
            installed,
            now(),
            max,
            &signing_key().verifying_key().to_bytes(),
        )
    }

    #[test]
    fn accepts_a_valid_signed_update() {
        let payload = b"blackshard signed rules v1";
        let envelope = signed_envelope(7, payload);
        let verified = verify(&envelope, payload, 6, 1_024).unwrap();
        assert_eq!(verified.manifest.sequence, 7);
        assert_eq!(verified.payload_sha256, Sha256::digest(payload).as_slice());
    }

    #[test]
    fn rejects_an_invalid_signature() {
        let payload = b"rules";
        let mut envelope = signed_envelope(2, payload);
        envelope.manifest.version.push_str("-tampered");
        assert!(matches!(
            verify(&envelope, payload, 1, 1_024),
            Err(UpdateError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_expired_and_rollback_manifests() {
        let payload = b"rules";
        let mut expired = signed_envelope(9, payload);
        expired.manifest.issued_at = now() - chrono::Duration::days(1);
        expired.manifest.expires_at = now() - chrono::Duration::seconds(1);
        let key = signing_key();
        expired.signature_ed25519 = hex(&key
            .sign(&expired.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&expired, payload, 8, 1_024),
            Err(UpdateError::Expired { .. })
        ));

        let rollback = signed_envelope(8, payload);
        assert!(matches!(
            verify(&rollback, payload, 8, 1_024),
            Err(UpdateError::Rollback { .. })
        ));
    }

    #[test]
    fn manifest_is_bound_to_product_channel_and_expiry_horizon() {
        let payload = b"rules";
        let key = signing_key();

        let mut legacy_schema = signed_envelope(2, payload);
        legacy_schema.manifest.schema_version = 1;
        legacy_schema.signature_ed25519 = hex(&key
            .sign(&legacy_schema.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&legacy_schema, payload, 1, 1_024),
            Err(UpdateError::UnsupportedSchema { found: 1 })
        ));

        let mut wrong_product = signed_envelope(2, payload);
        wrong_product.manifest.product = "another-product".to_owned();
        wrong_product.signature_ed25519 = hex(&key
            .sign(&wrong_product.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&wrong_product, payload, 1, 1_024),
            Err(UpdateError::WrongProduct { .. })
        ));

        let mut wrong_channel = signed_envelope(2, payload);
        wrong_channel.manifest.channel = "nightly".to_owned();
        wrong_channel.signature_ed25519 = hex(&key
            .sign(&wrong_channel.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&wrong_channel, payload, 1, 1_024),
            Err(UpdateError::WrongChannel { .. })
        ));

        let mut far_future = signed_envelope(2, payload);
        far_future.manifest.expires_at = now() + chrono::Duration::days(8);
        far_future.signature_ed25519 = hex(&key
            .sign(&far_future.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&far_future, payload, 1, 1_024),
            Err(UpdateError::ExpiryTooFar { .. })
        ));

        let mut future_issued = signed_envelope(2, payload);
        future_issued.manifest.issued_at = now() + chrono::Duration::minutes(16);
        future_issued.manifest.expires_at =
            future_issued.manifest.issued_at + chrono::Duration::days(1);
        future_issued.signature_ed25519 = hex(&key
            .sign(&future_issued.manifest.signing_bytes().unwrap())
            .to_bytes());
        assert!(matches!(
            verify(&future_issued, payload, 1, 1_024),
            Err(UpdateError::IssuedInFuture { .. })
        ));
    }

    #[test]
    fn terminal_sequence_value_is_reserved() {
        let payload = b"rules";
        let envelope = signed_envelope(u64::MAX, payload);
        assert!(matches!(
            verify(&envelope, payload, 1, 1_024),
            Err(UpdateError::SequenceOutOfRange {
                found: u64::MAX,
                maximum: MAX_UPDATE_SEQUENCE
            })
        ));
    }

    #[test]
    fn rejects_oversized_wrong_size_and_wrong_hash_payloads() {
        let payload = b"123456789";
        let envelope = signed_envelope(2, payload);
        assert!(matches!(
            verify(&envelope, payload, 1, 8),
            Err(UpdateError::Oversized { .. })
        ));
        assert!(matches!(
            verify(&envelope, b"short", 1, 1_024),
            Err(UpdateError::SizeMismatch { .. })
        ));
        assert!(matches!(
            verify(&envelope, b"abcdefghi", 1, 1_024),
            Err(UpdateError::HashMismatch)
        ));
    }

    #[test]
    fn rejects_non_https_or_credentialed_urls() {
        for unsafe_url in [
            "http://updates.blackshard.dev/rules",
            "file:///C:/rules",
            "https://user:password@updates.blackshard.dev/rules",
            "https://updates.blackshard.dev/rules#ignored-fragment",
        ] {
            let payload = b"rules";
            let mut envelope = signed_envelope(2, payload);
            envelope.manifest.payload_url = unsafe_url.to_owned();
            let key = signing_key();
            envelope.signature_ed25519 = hex(&key
                .sign(&envelope.manifest.signing_bytes().unwrap())
                .to_bytes());
            assert!(matches!(
                verify(&envelope, payload, 1, 1_024),
                Err(UpdateError::NonHttpsUrl)
            ));
        }
    }

    #[test]
    fn activation_is_versioned_and_retains_last_known_good() {
        let directory = TestDirectory::new();
        let store = UpdateStore::new(&directory.0, 1_024).unwrap();
        let public_key = signing_key().verifying_key().to_bytes();

        let first_payload = b"first rules";
        let first = signed_envelope(10, first_payload);
        let first_active = store
            .stage_and_activate(&first, first_payload, now(), &public_key)
            .unwrap();
        assert_eq!(fs::read(&first_active.payload_path).unwrap(), first_payload);
        assert!(store.last_known_good().unwrap().is_none());

        let second_payload = b"second rules";
        let second = signed_envelope(11, second_payload);
        let second_active = store
            .stage_and_activate(&second, second_payload, now(), &public_key)
            .unwrap();

        assert_eq!(store.current().unwrap().unwrap(), second_active);
        assert_eq!(store.installed_sequence().unwrap(), 11);
        let previous = store.last_known_good().unwrap().unwrap();
        assert_eq!(previous.sequence, 10);
        assert_eq!(fs::read(previous.payload_path).unwrap(), first_payload);
        assert_eq!(
            fs::read(second_active.payload_path).unwrap(),
            second_payload
        );
    }

    #[test]
    fn store_rejects_a_rollback_without_changing_current() {
        let directory = TestDirectory::new();
        let store = UpdateStore::new(&directory.0, 1_024).unwrap();
        let public_key = signing_key().verifying_key().to_bytes();
        let payload = b"rules";
        let current = signed_envelope(20, payload);
        store
            .stage_and_activate(&current, payload, now(), &public_key)
            .unwrap();

        let rollback = signed_envelope(19, payload);
        assert!(matches!(
            store.stage_and_activate(&rollback, payload, now(), &public_key),
            Err(UpdateError::Rollback { .. })
        ));
        assert_eq!(store.installed_sequence().unwrap(), 20);
    }

    #[test]
    fn manifest_v2_can_advance_a_v1_pointer_without_accepting_v1_manifests() {
        let directory = TestDirectory::new();
        let state = directory.0.join("state");
        fs::create_dir_all(&state).unwrap();
        let prior = ActivationPointer {
            schema_version: ACTIVATION_POINTER_SCHEMA_VERSION,
            sequence: 5,
            version: "legacy-v1".to_owned(),
            expires_at: now() + chrono::Duration::hours(1),
            payload_sha256: "11".repeat(32),
        };
        fs::write(
            state.join(CURRENT_POINTER_FILE),
            serde_json::to_vec(&prior).unwrap(),
        )
        .unwrap();

        let store = UpdateStore::new(&directory.0, 1_024).unwrap();
        assert_eq!(store.installed_sequence().unwrap(), 5);
        let payload = b"v2 definitions";
        store
            .stage_and_activate(
                &signed_envelope(6, payload),
                payload,
                now(),
                &signing_key().verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(store.installed_sequence().unwrap(), 6);
    }

    #[test]
    fn envelope_parser_is_bounded_and_rejects_unknown_fields() {
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            SignedUpdateEnvelope::from_json(&oversized),
            Err(UpdateError::EnvelopeTooLarge { .. })
        ));

        let payload = b"rules";
        let envelope = signed_envelope(1, payload);
        let mut value = serde_json::to_value(envelope).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            SignedUpdateEnvelope::from_json(&serde_json::to_vec(&value).unwrap()),
            Err(UpdateError::Serialization(_))
        ));
    }

    #[test]
    fn scheduler_stays_inside_the_jitter_window() {
        let scheduler = UpdateScheduler::default();
        let minimum = UPDATE_CHECK_INTERVAL - UPDATE_CHECK_JITTER;
        let maximum = UPDATE_CHECK_INTERVAL + UPDATE_CHECK_JITTER;
        assert_eq!(scheduler.delay_for_sample(0), minimum);
        assert_eq!(
            scheduler.delay_for_sample(UPDATE_CHECK_JITTER.as_secs() * 2),
            maximum
        );
        for sample in [1, 42, u32::MAX as u64, u64::MAX] {
            let delay = scheduler.delay_for_sample(sample);
            assert!(delay >= minimum && delay <= maximum);
        }
    }
}
