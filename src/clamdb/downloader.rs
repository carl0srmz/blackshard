//! Fetches and unpacks ClamAV definition containers without any ClamAV binaries.
//!
//! This previously shelled out to `freshclam.exe` to download and `sigtool.exe` to validate and
//! unpack. Both are now handled natively: the containers are plain HTTPS downloads and
//! [`crate::clamdb::cvd`] reads the format directly.
//!
//! Only `main` and `daily` are fetched. `bytecode.cvd` carries nothing but `.cbc` programs for
//! ClamAV's bytecode virtual machine, which blackshard does not implement, so downloading it would
//! cost bandwidth for signatures that could never be evaluated.
//!
//! An update asks the mirror for each container's 512 byte header first, and only downloads a
//! container whose version has changed. Unchanged containers are carried into the new generation
//! as hard links. Only the unpacked databases are kept, and each successful update deletes every
//! older generation, so the store holds one copy of the definitions rather than accumulating a new
//! one every refresh.

use chrono::{DateTime, Utc};
use log::{info, warn};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::clamdb::cvd;

const ACTIVE_POINTER: &str = "active.json";

/// Records the earliest time the mirror may be contacted again after it rate limited us.
const COOLDOWN_FILE: &str = "cooldown";

/// Wait applied to a 429 that does not say how long to wait.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// Upper bound on an honoured `Retry-After`, so a bogus value cannot stop updates indefinitely.
const MAX_COOLDOWN: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The containers blackshard consumes, in the order they are applied.
const CONTAINERS: [&str; 2] = ["main", "daily"];

const DEFAULT_MIRROR: &str = "https://database.clamav.net";

/// blackshard's own copy of the containers, refreshed by `.github/workflows/clamav-mirror.yml`.
///
/// The official mirror rate limits by address, so a machine that downloaded the full set a few
/// times (a test VM reverted to a checkpoint, say) can be refused for most of a day while it has no
/// definitions at all. Only then is this copy used. Every container carries ClamAV's signature,
/// verified the same way whichever mirror served it, so the copy is no less trustworthy.
const FALLBACK_MIRROR: &str =
    "https://github.com/carlosrmz009/blackshard/releases/download/clamav-mirror";

/// User-Agent sent to the official mirror.
///
/// `database.clamav.net` answers 403 to anything whose User-Agent does not begin with `ClamAV/` or
/// `CVDUPDATE/`; a plain product token, and even `curl`, is rejected outright. The `ClamAV/` prefix
/// is therefore a compatibility token, and blackshard is named in the comment field so the traffic
/// remains attributable.
///
/// This is a stopgap, and it should not survive real deployment: at scale every endpoint polling
/// Cisco directly is both abusive and fragile. The intended end state is a mirror blackshard
/// operates, filled by `cvdupdate` and published through its own signed feed, with endpoints
/// pointed at it through `BLACKSHARD_CLAMAV_MIRROR` until the default can change.
const USER_AGENT: &str = concat!(
    "ClamAV/1.4.1 (blackshard/",
    env!("CARGO_PKG_VERSION"),
    "; +https://blackshard.dev)"
);

/// Generous ceiling for one container. `main.cvd` sits comfortably under this today.
const MAX_CONTAINER_BYTES: u64 = 512 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Minimum age before a cached generation is checked against the mirror again.
const REFRESH_INTERVAL_MINUTES: i64 = 60;

#[derive(Debug)]
pub enum DownloadError {
    Io(io::Error),
    Http(String),
    Validation(String),
    /// The mirror refused us with 429 (or 503) and asked us to wait this long.
    RateLimited(Duration),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Http(error) => formatter.write_str(error),
            Self::Validation(error) => formatter.write_str(error),
            Self::RateLimited(wait) => write!(
                formatter,
                "the ClamAV mirror is rate limiting this machine; not contacting it for {} more seconds",
                wait.as_secs()
            ),
        }
    }
}

impl std::error::Error for DownloadError {}

impl From<io::Error> for DownloadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<cvd::CvdError> for DownloadError {
    fn from(error: cvd::CvdError) -> Self {
        match error {
            cvd::CvdError::Io(error) => Self::Io(error),
            cvd::CvdError::Malformed(detail) => Self::Validation(detail),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDatabase {
    pub generation: u64,
    pub version: String,
    pub activated_at: DateTime<Utc>,
    pub path: PathBuf,
    pub unpacked_path: PathBuf,
    /// The version of each container in this generation, compared against the mirror's headers
    /// so an unchanged container is never downloaded again. Pointers written before this field
    /// existed lack it, which simply forces one full refresh.
    #[serde(default)]
    pub container_versions: BTreeMap<String, u64>,
    /// When the mirror last confirmed it had nothing newer. `activated_at` stays the time these
    /// definitions were installed, which is the age the UI reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
}

impl ActiveDatabase {
    fn last_contact(&self) -> DateTime<Utc> {
        self.checked_at
            .map_or(self.activated_at, |checked| checked.max(self.activated_at))
    }
}

/// Whether the installed copy of a container can stand in for the one the mirror offers.
///
/// An older offer is never installed over a newer copy: a lagging CDN node serves one routinely,
/// and a hostile mirror could replay an old container whose ClamAV signature is still valid.
fn installed_is_current(installed: Option<u64>, offered: Option<u64>) -> bool {
    matches!((installed, offered), (Some(installed), Some(offered)) if installed >= offered)
}

/// The mirror containers are fetched from, overridable for testing and for private mirrors.
fn mirror() -> String {
    std::env::var("BLACKSHARD_CLAMAV_MIRROR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MIRROR.to_owned())
}

pub fn download_databases(blackshard_data: &Path) -> Result<ActiveDatabase, DownloadError> {
    download_databases_with_fallback(blackshard_data, FALLBACK_MIRROR)
}

fn download_databases_with_fallback(
    blackshard_data: &Path,
    fallback: &str,
) -> Result<ActiveDatabase, DownloadError> {
    let previous = active_database(blackshard_data).ok();
    if let Some(active) = &previous {
        if Utc::now()
            .signed_duration_since(active.last_contact())
            .num_minutes()
            < REFRESH_INTERVAL_MINUTES
        {
            return Ok(active.clone());
        }
    }

    // A mirror that rate limited us is left alone until the time it asked for. Calling back
    // early is what gets a client blocked for longer, and the current definitions keep working.
    let clam_root = blackshard_data.join("ClamAV");
    let cooldown_path = clam_root.join(COOLDOWN_FILE);
    if let Some(remaining) = cooldown_remaining(&cooldown_path) {
        return match previous {
            Some(active) => {
                info!(
                    "{}; keeping the current definitions",
                    DownloadError::RateLimited(remaining)
                );
                Ok(active)
            }
            None => from_fallback(&clam_root, fallback, DownloadError::RateLimited(remaining)),
        };
    }

    let had_definitions = previous.is_some();
    let result = match refresh(&clam_root, previous, &mirror()) {
        Err(DownloadError::RateLimited(wait)) => {
            let until = Utc::now() + chrono::Duration::from_std(wait).unwrap_or_default();
            if let Err(error) =
                crate::atomic_file::write(&cooldown_path, until.to_rfc3339().as_bytes())
            {
                warn!("could not record the mirror's cooldown: {error}");
            }
            Err(DownloadError::RateLimited(wait))
        }
        other => other,
    };
    match result {
        Err(error) if !had_definitions => from_fallback(&clam_root, fallback, error),
        other => other,
    }
}

/// Fetches the definitions from blackshard's copy for a machine the official mirror refused.
fn from_fallback(
    clam_root: &Path,
    fallback: &str,
    primary: DownloadError,
) -> Result<ActiveDatabase, DownloadError> {
    warn!("{primary}; fetching the definitions from blackshard's copy instead");
    refresh(clam_root, None, fallback).map_err(|error| {
        DownloadError::Http(format!("{primary}; blackshard's copy failed too: {error}"))
    })
}

/// How long is left on a recorded cooldown, if it has not yet passed.
fn cooldown_remaining(path: &Path) -> Option<Duration> {
    let text = fs::read_to_string(path).ok()?;
    let until = DateTime::parse_from_rfc3339(text.trim()).ok()?;
    (until.with_timezone(&Utc) - Utc::now()).to_std().ok()
}

fn refresh(
    clam_root: &Path,
    previous: Option<ActiveDatabase>,
    base: &str,
) -> Result<ActiveDatabase, DownloadError> {
    // Ask the mirror what it has before downloading anything. Each header is signed, so a
    // tampered version number cannot be used to suppress an update.
    let mut remote_versions = BTreeMap::new();
    for name in CONTAINERS {
        let header = fetch_header(base, name)?;
        cvd::verify_signature(&header)?;
        remote_versions.insert(name.to_owned(), header.version);
    }
    if let Some(active) = previous.as_ref().filter(|active| {
        CONTAINERS.iter().all(|name| {
            installed_is_current(
                active.container_versions.get(*name).copied(),
                remote_versions.get(*name).copied(),
            )
        })
    }) {
        if active.container_versions != remote_versions {
            warn!(
                "the ClamAV mirror offers {remote_versions:?}, older than the installed {:?}; keeping the installed definitions",
                active.container_versions
            );
        } else {
            info!("ClamAV definitions are current ({remote_versions:?}); nothing to download");
        }
        let mut active = active.clone();
        active.checked_at = Some(Utc::now());
        // Without this the 60 minute short-circuit never applies again once the definitions are
        // more than an hour old, and every scheduler tick goes back to the mirror.
        if let Err(error) = write_active_pointer(clam_root, &active) {
            warn!("could not record the mirror check: {error}");
        }
        return Ok(active);
    }

    let staging_root = clam_root.join("Staging");
    // Anything still in Staging is an attempt that failed or was interrupted.
    remove_dir_if_present(&staging_root);

    let generation: u64 = Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| DownloadError::Validation("system clock predates Unix epoch".to_owned()))?;
    let staging_dir = staging_root.join(generation.to_string());
    let unpacked_dir = staging_dir.join("Unpacked");
    fs::create_dir_all(&unpacked_dir)?;

    let container_versions = match populate_generation(
        base,
        previous.as_ref(),
        &remote_versions,
        &staging_dir,
        &unpacked_dir,
    ) {
        Ok(versions) => versions,
        Err(error) => {
            remove_dir_if_present(&staging_dir);
            return Err(error);
        }
    };

    let generations_dir = clam_root.join("Generations");
    fs::create_dir_all(&generations_dir)?;
    let generation_dir = generations_dir.join(generation.to_string());
    fs::rename(&staging_dir, &generation_dir)?;

    let active = ActiveDatabase {
        generation,
        version: container_versions
            .get("daily")
            .map(u64::to_string)
            .unwrap_or_else(|| generation.to_string()),
        activated_at: Utc::now(),
        path: generation_dir.clone(),
        unpacked_path: generation_dir.join("Unpacked"),
        container_versions,
        checked_at: None,
    };
    write_active_pointer(clam_root, &active)?;
    info!(
        "Activated ClamAV definition generation {} ({:?})",
        active.generation, active.container_versions
    );

    // Unchanged containers were hard linked, so removing old generations frees their space
    // without disturbing the files the new generation shares with them.
    prune_generations(&generations_dir, &generation_dir);
    Ok(active)
}

/// Fills a staging generation, downloading only the containers whose version changed.
///
/// Returns the version of each container actually installed, which can be newer than the header
/// check saw if the mirror published in between.
fn populate_generation(
    base: &str,
    previous: Option<&ActiveDatabase>,
    remote_versions: &BTreeMap<String, u64>,
    staging_dir: &Path,
    unpacked_dir: &Path,
) -> Result<BTreeMap<String, u64>, DownloadError> {
    let mut installed = BTreeMap::new();
    for name in CONTAINERS {
        let unchanged = previous.filter(|active| {
            installed_is_current(
                active.container_versions.get(name).copied(),
                remote_versions.get(name).copied(),
            )
        });
        if let Some(active) = unchanged {
            let linked = link_container_files(&active.unpacked_path, unpacked_dir, name)?;
            info!("Reused unchanged {name} definitions ({linked} files)");
            installed.insert(name.to_owned(), active.container_versions[name]);
            continue;
        }

        let container = staging_dir.join(format!("{name}.cvd"));
        fetch_container(base, name, &container)?;
        let header = verify_container(&container)?;
        // The header check above saw a newer version, but the body can come from another node.
        if let Some(installed) = previous.and_then(|active| active.container_versions.get(name)) {
            if header.version < *installed {
                return Err(DownloadError::Validation(format!(
                    "the mirror served {name}.cvd version {}, older than the installed {installed}",
                    header.version
                )));
            }
        }
        let (_, extracted) = cvd::extract(&container, unpacked_dir)?;
        // The unpacked databases are all blackshard reads, so the container itself is not kept.
        fs::remove_file(&container)?;
        info!(
            "Unpacked {name}.cvd version {} with {} signatures into {} files",
            header.version,
            header.signature_count,
            extracted.len()
        );
        installed.insert(name.to_owned(), header.version);
    }
    Ok(installed)
}

/// Carries one container's unpacked files into a new generation.
///
/// Hard links make this free in both time and space; a copy is the fallback where linking is
/// refused. Files are selected by the `<container>.` prefix every database inside a container
/// carries, which is also how `daily` and `main` stay separate in the shared directory.
fn link_container_files(from: &Path, to: &Path, container: &str) -> Result<usize, DownloadError> {
    let prefix = format!("{container}.");
    let mut linked = 0;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) || !entry.file_type()?.is_file() {
            continue;
        }
        let target = to.join(name);
        if fs::hard_link(entry.path(), &target).is_err() {
            fs::copy(entry.path(), &target)?;
        }
        linked += 1;
    }
    if linked == 0 {
        return Err(DownloadError::Validation(format!(
            "the previous generation holds no {container} databases to reuse"
        )));
    }
    Ok(linked)
}

/// Deletes every generation except the one just activated.
///
/// A failure here only costs disk space and is retried on the next update, so it is logged rather
/// than failing an update that has already been activated.
fn prune_generations(generations_dir: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(generations_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path != keep && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            if let Err(error) = fs::remove_dir_all(&path) {
                warn!("could not remove old definition generation {path:?}: {error}");
            }
        }
    }
}

fn remove_dir_if_present(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => warn!("could not remove {path:?}: {error}"),
    }
}

fn container_url(base: &str, name: &str) -> Result<String, DownloadError> {
    let url = format!("{}/{name}.cvd", base.trim_end_matches('/'));
    if !url.starts_with("https://") {
        return Err(DownloadError::Validation(format!(
            "the configured ClamAV mirror is not an HTTPS origin: {url}"
        )));
    }
    Ok(url)
}

/// Turns a failed request into an error, recognising the mirror's request to back off.
fn request_error(url: &str, error: ureq::Error) -> DownloadError {
    match error {
        ureq::Error::Status(status @ (429 | 503), response) => {
            let asked = response
                .header("Retry-After")
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            match asked {
                Some(wait) => DownloadError::RateLimited(wait.min(MAX_COOLDOWN)),
                None if status == 429 => DownloadError::RateLimited(DEFAULT_COOLDOWN),
                None => DownloadError::Http(format!("{url} is temporarily unavailable ({status})")),
            }
        }
        other => DownloadError::Http(format!("could not fetch {url}: {other}")),
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build()
}

/// Reads just a container's header, which carries its version, with a ranged request.
///
/// A mirror that ignores the range still works: only the first 512 bytes are read before the
/// connection is dropped.
fn fetch_header(base: &str, name: &str) -> Result<cvd::CvdHeader, DownloadError> {
    let url = container_url(base, name)?;
    let response = agent()
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .set("Range", &format!("bytes=0-{}", cvd::HEADER_LEN - 1))
        .call()
        .map_err(|error| request_error(&url, error))?;
    let mut block = Vec::with_capacity(cvd::HEADER_LEN);
    response
        .into_reader()
        .take(cvd::HEADER_LEN as u64)
        .read_to_end(&mut block)?;
    Ok(cvd::CvdHeader::parse(&block)?)
}

/// Streams one container to disk over HTTPS.
fn fetch_container(base: &str, name: &str, destination: &Path) -> Result<(), DownloadError> {
    let url = container_url(base, name)?;
    let response = agent()
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|error| request_error(&url, error))?;

    let mut reader = response.into_reader().take(MAX_CONTAINER_BYTES + 1);
    let mut file = File::create(destination)?;
    let copied = io::copy(&mut reader, &mut file)?;
    file.flush()?;

    if copied > MAX_CONTAINER_BYTES {
        let _ = fs::remove_file(destination);
        return Err(DownloadError::Validation(format!(
            "{name}.cvd exceeded the {MAX_CONTAINER_BYTES} byte ceiling"
        )));
    }
    if copied <= cvd::HEADER_LEN as u64 {
        let _ = fs::remove_file(destination);
        return Err(DownloadError::Validation(format!(
            "{name}.cvd was truncated to {copied} bytes"
        )));
    }
    Ok(())
}

/// Authenticates a downloaded container: ClamAV signed its digest, and its body has that digest.
fn verify_container(path: &Path) -> Result<cvd::CvdHeader, DownloadError> {
    let header = verify_body_digest(path)?;
    cvd::verify_signature(&header)?;
    Ok(header)
}

/// Confirms the container body matches the MD5 recorded in its own header.
fn verify_body_digest(path: &Path) -> Result<cvd::CvdHeader, DownloadError> {
    let header = cvd::read_header(path)?;

    let mut file = File::open(path)?;
    let mut skip = [0u8; cvd::HEADER_LEN];
    file.read_exact(&mut skip)?;

    let mut hasher = Md5::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex::encode(hasher.finalize());

    if !digest.eq_ignore_ascii_case(&header.md5) {
        return Err(DownloadError::Validation(format!(
            "{} failed its integrity check: header declared {} but the body hashed to {digest}",
            path.display(),
            header.md5
        )));
    }
    Ok(header)
}

pub fn active_database(blackshard_data: &Path) -> Result<ActiveDatabase, DownloadError> {
    let pointer_path = blackshard_data.join("ClamAV").join(ACTIVE_POINTER);
    let bytes = fs::read(&pointer_path)?;
    let active: ActiveDatabase = serde_json::from_slice(&bytes)
        .map_err(|error| DownloadError::Validation(format!("invalid active pointer: {error}")))?;
    let canonical_root = fs::canonicalize(blackshard_data.join("ClamAV").join("Generations"))?;
    let canonical_unpacked = fs::canonicalize(&active.unpacked_path)?;
    // Every container ships a `<name>.info` manifest, so its presence shows the container was
    // unpacked into this generation.
    if !canonical_unpacked.starts_with(&canonical_root)
        || !CONTAINERS
            .iter()
            .all(|name| active.unpacked_path.join(format!("{name}.info")).is_file())
    {
        return Err(DownloadError::Validation(
            "the active ClamAV generation is missing or outside the protected store".to_owned(),
        ));
    }
    Ok(active)
}

fn write_active_pointer(clam_root: &Path, active: &ActiveDatabase) -> Result<(), DownloadError> {
    let pointer = clam_root.join(ACTIVE_POINTER);
    let bytes = serde_json::to_vec_pretty(active)
        .map_err(|error| DownloadError::Validation(error.to_string()))?;
    crate::atomic_file::write(&pointer, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a container whose header MD5 agrees (or deliberately disagrees) with its body.
    fn container(body: &[u8], declared_md5: Option<&str>) -> Vec<u8> {
        let digest = declared_md5
            .map(str::to_owned)
            .unwrap_or_else(|| hex::encode(Md5::digest(body)));
        let text = format!(
            "ClamAV-VDB:16 Sep 2026 09-00 +0000:27000:2000000:90:{digest}:{}:blackshard:1758009600",
            "a".repeat(40)
        );
        let mut out = text.into_bytes();
        out.resize(cvd::HEADER_LEN, b' ');
        out.extend_from_slice(body);
        out
    }

    /// Lays out a store with one activated generation holding `files` in its `Unpacked` folder.
    fn store_with_generation(root: &Path, generation: u64, files: &[&str]) -> ActiveDatabase {
        let path = root
            .join("ClamAV")
            .join("Generations")
            .join(generation.to_string());
        let unpacked = path.join("Unpacked");
        fs::create_dir_all(&unpacked).unwrap();
        for file in files {
            fs::write(unpacked.join(file), file.as_bytes()).unwrap();
        }
        let active = ActiveDatabase {
            generation,
            version: "1".to_owned(),
            activated_at: Utc::now(),
            path,
            unpacked_path: unpacked,
            container_versions: BTreeMap::from([("main".to_owned(), 63), ("daily".to_owned(), 1)]),
            checked_at: None,
        };
        write_active_pointer(&root.join("ClamAV"), &active).unwrap();
        active
    }

    #[test]
    fn accepts_a_container_whose_body_matches_its_header_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daily.cvd");
        fs::write(&path, container(b"definition archive bytes", None)).unwrap();

        let header = verify_body_digest(&path).unwrap();
        assert_eq!(header.version, 27_000);
    }

    #[test]
    fn rejects_a_container_whose_body_was_altered() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daily.cvd");
        fs::write(
            &path,
            container(b"definition archive bytes", Some(&"0".repeat(32))),
        )
        .unwrap();

        let error = verify_body_digest(&path).unwrap_err();
        assert!(
            matches!(&error, DownloadError::Validation(detail) if detail.contains("integrity")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_container_without_a_genuine_signature_is_rejected() {
        // The body digest is correct, but nobody holding ClamAV's key signed it.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daily.cvd");
        fs::write(&path, container(b"definition archive bytes", None)).unwrap();

        assert!(verify_body_digest(&path).is_ok());
        assert!(verify_container(&path).is_err());
    }

    #[test]
    fn rejects_a_non_https_mirror() {
        let directory = tempfile::tempdir().unwrap();
        for error in [
            fetch_container(
                "http://insecure.example",
                "daily",
                &directory.path().join("d.cvd"),
            )
            .unwrap_err(),
            fetch_header("http://insecure.example", "daily").unwrap_err(),
        ] {
            assert!(
                matches!(&error, DownloadError::Validation(detail) if detail.contains("HTTPS")),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn the_mirror_defaults_to_the_official_origin() {
        // The environment variable is not set in a clean test run.
        if std::env::var_os("BLACKSHARD_CLAMAV_MIRROR").is_none() {
            assert_eq!(mirror(), DEFAULT_MIRROR);
        }
    }

    #[test]
    fn an_absent_pointer_is_reported_rather_than_panicking() {
        let directory = tempfile::tempdir().unwrap();
        assert!(active_database(directory.path()).is_err());
    }

    #[test]
    fn an_activated_generation_is_found_by_its_manifests() {
        let directory = tempfile::tempdir().unwrap();
        store_with_generation(directory.path(), 1, &["main.info", "daily.info"]);
        let active = active_database(directory.path()).unwrap();
        assert_eq!(active.container_versions["main"], 63);

        // A generation missing a container's manifest is not trusted.
        let directory = tempfile::tempdir().unwrap();
        store_with_generation(directory.path(), 1, &["main.info"]);
        assert!(active_database(directory.path()).is_err());
    }

    #[test]
    fn a_pointer_from_an_older_build_forces_one_full_refresh() {
        let pointer = r#"{"generation":1,"version":"28128","activated_at":"2026-09-19T00:00:00Z",
            "path":"C:\\x","unpacked_path":"C:\\x\\Unpacked"}"#;
        let active: ActiveDatabase = serde_json::from_str(pointer).unwrap();
        // No recorded versions can never equal the mirror's, so everything is downloaded once.
        assert!(active.container_versions.is_empty());
    }

    #[test]
    fn unchanged_containers_are_carried_over_without_the_others() {
        let directory = tempfile::tempdir().unwrap();
        let active = store_with_generation(
            directory.path(),
            1,
            &[
                "main.info",
                "main.hsb",
                "daily.info",
                "daily.hsb",
                "COPYING",
            ],
        );
        let target = directory.path().join("next");
        fs::create_dir_all(&target).unwrap();

        assert_eq!(
            link_container_files(&active.unpacked_path, &target, "main").unwrap(),
            2
        );
        let mut names: Vec<_> = fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["main.hsb", "main.info"]);
        assert_eq!(fs::read(target.join("main.hsb")).unwrap(), b"main.hsb");

        // Removing the generation the files came from must not take them with it.
        fs::remove_dir_all(&active.path).unwrap();
        assert_eq!(fs::read(target.join("main.hsb")).unwrap(), b"main.hsb");
    }

    #[test]
    fn an_older_container_never_replaces_a_newer_one() {
        assert!(installed_is_current(Some(27_800), Some(27_800)));
        // A lagging or replaying mirror: keep what is installed.
        assert!(installed_is_current(Some(27_800), Some(27_799)));
        assert!(!installed_is_current(Some(27_800), Some(27_801)));
        // Nothing installed, or nothing offered, is never "current".
        assert!(!installed_is_current(None, Some(1)));
        assert!(!installed_is_current(Some(1), None));
    }

    #[test]
    fn a_confirmed_check_counts_as_recent_contact() {
        let directory = tempfile::tempdir().unwrap();
        let mut active = store_with_generation(directory.path(), 1, &["main.info", "daily.info"]);
        active.activated_at = Utc::now() - chrono::Duration::days(3);
        assert_eq!(active.last_contact(), active.activated_at);
        let checked = Utc::now();
        active.checked_at = Some(checked);
        assert_eq!(active.last_contact(), checked);

        // The field round-trips through the pointer, and old pointers without it still load.
        write_active_pointer(&directory.path().join("ClamAV"), &active).unwrap();
        let reloaded = active_database(directory.path()).unwrap();
        assert_eq!(reloaded.checked_at, Some(checked));
    }

    #[test]
    fn reusing_a_container_that_is_not_there_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let active = store_with_generation(directory.path(), 1, &["daily.info"]);
        let target = directory.path().join("next");
        fs::create_dir_all(&target).unwrap();
        assert!(link_container_files(&active.unpacked_path, &target, "main").is_err());
    }

    fn status(response: &str) -> ureq::Error {
        let response: ureq::Response = response.parse().unwrap();
        ureq::Error::Status(response.status(), response)
    }

    #[test]
    fn rate_limiting_honours_retry_after_within_bounds() {
        let limited = |response| request_error("https://mirror.example", status(response));
        assert!(matches!(
            limited("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 86390\r\n\r\n"),
            DownloadError::RateLimited(wait) if wait == Duration::from_secs(86_390)
        ));
        assert!(matches!(
            limited("HTTP/1.1 429 Too Many Requests\r\n\r\n"),
            DownloadError::RateLimited(wait) if wait == DEFAULT_COOLDOWN
        ));
        assert!(matches!(
            limited("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 99999999\r\n\r\n"),
            DownloadError::RateLimited(wait) if wait == MAX_COOLDOWN
        ));
        assert!(matches!(
            limited("HTTP/1.1 404 Not Found\r\n\r\n"),
            DownloadError::Http(_)
        ));
    }

    #[test]
    fn a_recorded_cooldown_keeps_the_current_definitions_without_contacting_the_mirror() {
        let directory = tempfile::tempdir().unwrap();
        let mut active = store_with_generation(directory.path(), 1, &["main.info", "daily.info"]);
        // Old enough that, without the cooldown, the mirror would be asked for new headers.
        active.activated_at = Utc::now() - chrono::Duration::hours(12);
        write_active_pointer(&directory.path().join("ClamAV"), &active).unwrap();
        let until = Utc::now() + chrono::Duration::hours(1);
        fs::write(
            directory.path().join("ClamAV").join(COOLDOWN_FILE),
            until.to_rfc3339(),
        )
        .unwrap();

        // A non-HTTPS fallback fails before any request, so neither mirror is contacted.
        let fallback = "http://fallback.invalid";
        let kept = download_databases_with_fallback(directory.path(), fallback).unwrap();
        assert_eq!(kept.generation, 1);

        // With no definitions at all, blackshard's copy is tried, and both failures reported.
        fs::remove_file(directory.path().join("ClamAV").join(ACTIVE_POINTER)).unwrap();
        let error = download_databases_with_fallback(directory.path(), fallback)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rate limiting"), "{error}");
        assert!(error.contains("fallback.invalid"), "{error}");
    }

    /// Fetches, verifies and unpacks the real containers from blackshard's copy. Run it with
    /// `cargo test --lib -- --ignored fallback_mirror` after changing the mirror or the downloader.
    #[test]
    #[ignore = "downloads about 110 MB"]
    fn the_fallback_mirror_serves_verifiable_definitions() {
        let directory = tempfile::tempdir().unwrap();
        refresh(&directory.path().join("ClamAV"), None, FALLBACK_MIRROR).unwrap();
        assert!(active_database(directory.path()).is_ok());
    }

    #[test]
    fn an_expired_or_unreadable_cooldown_is_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(COOLDOWN_FILE);
        assert!(cooldown_remaining(&path).is_none());
        fs::write(
            &path,
            (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
        )
        .unwrap();
        assert!(cooldown_remaining(&path).is_none());
        fs::write(&path, "not a timestamp").unwrap();
        assert!(cooldown_remaining(&path).is_none());
    }

    #[test]
    fn pruning_keeps_only_the_active_generation() {
        let directory = tempfile::tempdir().unwrap();
        let generations = directory.path().join("Generations");
        for generation in ["1", "2", "3"] {
            fs::create_dir_all(generations.join(generation).join("Unpacked")).unwrap();
        }
        prune_generations(&generations, &generations.join("3"));

        let remaining: Vec<_> = fs::read_dir(&generations)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(remaining, ["3"]);
    }
}
