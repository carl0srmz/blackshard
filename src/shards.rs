//! Shards learned on this machine.
//!
//! When behaviour convicts a program that no signature knew, say the ransomware monitor stopping an
//! unsigned process that was encrypting documents, the program's SHA-256 becomes a shard. From then
//! on that exact file is blocked and quarantined on sight, wherever it turns up, without waiting
//! for anyone's definition update. This is the local half of shardnet; the record is what peers
//! will gossip once the network exists.
//!
//! Shards live in one small JSON file under ProgramData, readable only by SYSTEM and
//! Administrators like the rest of that directory.

use crate::atomic_file;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

/// Plenty for one machine; a full set means something is learning far too eagerly.
const MAX_SHARDS: usize = 10_000;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Shard {
    pub sha256: String,
    pub threat_name: String,
    pub learned_at: DateTime<Utc>,
}

#[derive(Default)]
struct Store {
    /// Where learned shards persist; `None` keeps them in memory only, as tests do.
    path: Option<PathBuf>,
    by_digest: HashMap<String, Shard>,
}

fn store() -> &'static RwLock<Store> {
    static STORE: OnceLock<RwLock<Store>> = OnceLock::new();
    STORE.get_or_init(Default::default)
}

pub fn default_machine_path() -> PathBuf {
    crate::paths::state_dir().join("shards.json")
}

/// Loads the shards persisted at `path` and persists every later one there.
pub fn load(path: &Path) -> io::Result<usize> {
    let shards: Vec<Shard> = match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_FILE_BYTES => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the shard file exceeds its size limit",
            ))
        }
        Ok(_) => serde_json::from_slice(&std::fs::read(path)?).map_err(io::Error::other)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    let mut store = store()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    store.path = Some(path.to_path_buf());
    store.by_digest = shards
        .into_iter()
        .filter(|shard| is_sha256_hex(&shard.sha256))
        .take(MAX_SHARDS)
        .map(|shard| (shard.sha256.to_ascii_lowercase(), shard))
        .collect();
    Ok(store.by_digest.len())
}

/// The threat name learned for this whole-file digest, if any.
pub fn lookup(sha256: &str) -> Option<String> {
    let store = store().read().ok()?;
    if store.by_digest.is_empty() {
        return None;
    }
    store
        .by_digest
        .get(&sha256.to_ascii_lowercase())
        .map(|shard| shard.threat_name.clone())
}

/// Remembers `sha256` as `threat_name`. Returns whether it was new.
pub fn learn(sha256: &str, threat_name: &str) -> io::Result<bool> {
    if !is_sha256_hex(sha256) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a shard needs a whole-file SHA-256 digest",
        ));
    }
    let key = sha256.to_ascii_lowercase();
    let mut store = store()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if store.by_digest.contains_key(&key) {
        return Ok(false);
    }
    if store.by_digest.len() >= MAX_SHARDS {
        return Err(io::Error::other("the local shard set is full"));
    }
    store.by_digest.insert(
        key.clone(),
        Shard {
            sha256: key,
            threat_name: threat_name.to_owned(),
            learned_at: Utc::now(),
        },
    );
    // The shard is in force from here on even if it cannot be saved, so this still reports it as
    // new: callers invalidate cached clean verdicts on `Ok(true)`, and an error would leave them
    // serving the convicted file. It is saved again with the next shard learned.
    if let Err(error) = persist(&store) {
        log::warn!("A learned shard is active but could not be saved: {error}");
    }
    Ok(true)
}

/// Forgets a shard, for when the person restores the file it convicted.
pub fn forget(sha256: &str) -> io::Result<bool> {
    let mut store = store()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if store
        .by_digest
        .remove(&sha256.to_ascii_lowercase())
        .is_none()
    {
        return Ok(false);
    }
    persist(&store)?;
    Ok(true)
}

fn persist(store: &Store) -> io::Result<()> {
    let Some(path) = &store.path else {
        return Ok(());
    };
    let mut shards = store.by_digest.values().collect::<Vec<_>>();
    shards.sort_by_key(|shard| shard.learned_at);
    atomic_file::write(
        path,
        &serde_json::to_vec_pretty(&shards).map_err(io::Error::other)?,
    )
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learned_shards_are_found_case_insensitively_and_forgotten() {
        // Tests share the process-wide store, so this digest is used nowhere else.
        let digest = "5a".repeat(32);
        assert!(lookup(&digest).is_none());
        assert!(learn(&digest.to_ascii_uppercase(), "Shard.Test").unwrap());
        assert!(!learn(&digest, "Shard.Test").unwrap());
        assert_eq!(lookup(&digest).as_deref(), Some("Shard.Test"));
        assert!(forget(&digest).unwrap());
        assert!(lookup(&digest).is_none());
        assert!(learn("not a digest", "Shard.Test").is_err());
    }
}
