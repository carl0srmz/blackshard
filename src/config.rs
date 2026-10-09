use crate::atomic_file;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub schema_version: u32,
    pub real_time_protection: bool,

    pub ransomware_protection: bool,

    pub ransomware_block_mode: bool,
    pub automatic_quarantine: bool,
    pub notify_on_detection: bool,
    pub scan_archives: bool,
    pub scan_network_drives: bool,
    pub low_resource_mode: bool,
    pub max_file_size_mb: u64,
    pub worker_count: usize,
    pub definition_update_interval_hours: u64,
    pub exclusions: Vec<PathBuf>,
    /// `exclusions` resolved to comparison keys, computed on first use. See `is_excluded`.
    #[serde(skip)]
    exclusion_keys: OnceLock<Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(2);
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            real_time_protection: true,
            ransomware_protection: true,
            // Stopping the writer is the point; audit mode only watches files get encrypted.
            ransomware_block_mode: true,
            automatic_quarantine: true,
            notify_on_detection: true,
            scan_archives: true,
            scan_network_drives: false,
            low_resource_mode: true,
            max_file_size_mb: 512,
            worker_count: logical_cpus.saturating_sub(1).clamp(1, 4),
            definition_update_interval_hours: 4,
            exclusions: Vec::new(),
            exclusion_keys: OnceLock::new(),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        let mut settings: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        settings.validate();
        Ok(settings)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut validated = self.clone();
        validated.validate();
        let bytes = serde_json::to_vec_pretty(&validated).map_err(io::Error::other)?;
        atomic_file::write(path, &bytes)
    }

    pub fn default_machine_path() -> PathBuf {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("blackshard").join("settings.json")
    }

    /// Whether `path` is an exclusion or lies inside one.
    ///
    /// This runs for every real-time event, so it touches no file system: the exclusions are
    /// resolved once, and the candidate is compared as text. Callers therefore pass a path that is
    /// already final: the path of an opened handle, a kernel device path, or a path found under a
    /// canonicalised scan root.
    pub fn is_excluded(&self, path: &Path) -> bool {
        let candidate = comparison_key(path);
        self.exclusion_keys().iter().any(|exclusion| {
            candidate
                .strip_prefix(exclusion.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
        })
    }

    /// Each exclusion canonicalised, in both its drive-letter and kernel device form, since
    /// real-time events arrive as `\Device\HarddiskVolumeN\...` paths.
    fn exclusion_keys(&self) -> &[String] {
        self.exclusion_keys.get_or_init(|| {
            let mut keys = Vec::new();
            for exclusion in &self.exclusions {
                let key = resolved_key(exclusion);
                if let Some(device) = device_form(&key) {
                    keys.push(device);
                }
                keys.push(key);
            }
            keys
        })
    }

    pub fn add_exclusion(&mut self, path: PathBuf) {
        let key = resolved_key(&path);
        if !self.exclusions.iter().any(|item| resolved_key(item) == key) {
            self.exclusions.push(path);
            self.exclusion_keys = OnceLock::new();
        }
    }

    fn validate(&mut self) {
        self.schema_version = SETTINGS_SCHEMA_VERSION;
        self.max_file_size_mb = self.max_file_size_mb.clamp(1, 4_096);
        self.worker_count = self.worker_count.clamp(1, 16);
        self.definition_update_interval_hours = self.definition_update_interval_hours.clamp(1, 24);
        self.exclusions.sort_by_key(|path| resolved_key(path));
        self.exclusions
            .dedup_by(|left, right| resolved_key(left) == resolved_key(right));
        self.exclusion_keys = OnceLock::new();
    }
}

/// Canonicalises a path, then reduces it to its comparison key.
fn resolved_key(path: &Path) -> String {
    comparison_key(&canonicalize_with_missing_tail(path))
}

/// Case-folded path text without Win32 namespace prefixes or trailing separators, so
/// `\\?\C:\Temp\`, `C:/temp` and `\\?\GLOBALROOT\Device\X\temp` compare as their plain forms.
fn comparison_key(path: &Path) -> String {
    let lower = path.to_string_lossy().replace('/', "\\").to_lowercase();
    let key = if let Some(rest) = lower.strip_prefix(r"\\?\globalroot") {
        rest.to_owned()
    } else if let Some(rest) = lower.strip_prefix(r"\\?\unc\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = lower
        .strip_prefix(r"\\?\")
        .or_else(|| lower.strip_prefix(r"\??\"))
    {
        rest.to_owned()
    } else {
        lower
    };
    key.trim_end_matches('\\').to_owned()
}

/// Rewrites a `c:\...` key into the `\device\harddiskvolumen\...` form the minifilter reports.
#[cfg(windows)]
fn device_form(key: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

    let bytes = key.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let drive: Vec<u16> = key[..2].encode_utf16().chain([0]).collect();
    let mut target = vec![0u16; 1024];
    let written =
        unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    if written == 0 {
        return None;
    }
    // The result is a list of NUL-terminated names; the first is the current mapping.
    let device = target.split(|unit| *unit == 0).next()?;
    let device = String::from_utf16(device).ok()?.to_lowercase();
    Some(format!("{device}{}", &key[2..]))
}

#[cfg(not(windows))]
fn device_form(_key: &str) -> Option<String> {
    None
}

fn canonicalize_with_missing_tail(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }

    let mut cursor = path;
    let mut missing = Vec::new();
    while !cursor.exists() {
        if let Some(name) = cursor.file_name() {
            missing.push(name.to_os_string());
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        cursor = parent;
    }

    let mut rebuilt = fs::canonicalize(cursor).unwrap_or_else(|_| {
        if path.is_absolute() {
            cursor.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(cursor)
        }
    });
    for component in missing.into_iter().rev() {
        rebuilt.push(component);
    }
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_clamps_untrusted_values() {
        let mut settings = Settings {
            max_file_size_mb: u64::MAX,
            worker_count: 0,
            definition_update_interval_hours: 0,
            ..Settings::default()
        };
        settings.validate();
        assert_eq!(settings.max_file_size_mb, 4_096);
        assert_eq!(settings.worker_count, 1);
        assert_eq!(settings.definition_update_interval_hours, 1);
    }

    #[test]
    fn settings_round_trip_atomically() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("config").join("settings.json");
        let expected = Settings {
            real_time_protection: false,
            ..Settings::default()
        };
        expected.save(&path).unwrap();
        let actual = Settings::load(&path).unwrap();
        assert!(!actual.real_time_protection);
        assert_eq!(actual.schema_version, SETTINGS_SCHEMA_VERSION);
    }

    #[test]
    fn exclusions_are_path_component_aware() {
        let temporary = tempfile::tempdir().unwrap();
        let excluded = temporary.path().join("cache");
        fs::create_dir_all(&excluded).unwrap();
        let sibling = temporary.path().join("cache-not-excluded");
        fs::create_dir_all(&sibling).unwrap();
        let mut settings = Settings::default();
        settings.add_exclusion(excluded.clone());

        // Callers pass final paths, so the test does too.
        let excluded = fs::canonicalize(&excluded).unwrap();
        let sibling = fs::canonicalize(&sibling).unwrap();
        assert!(settings.is_excluded(&excluded.join("file.bin")));
        assert!(settings.is_excluded(&excluded));
        assert!(!settings.is_excluded(&sibling.join("file.bin")));
    }

    #[test]
    fn exclusions_match_the_forms_real_time_events_arrive_in() {
        let temporary = tempfile::tempdir().unwrap();
        let excluded = fs::canonicalize(temporary.path())
            .unwrap()
            .join("Build Cache");
        fs::create_dir_all(&excluded).unwrap();
        let mut settings = Settings::default();
        settings.add_exclusion(excluded.clone());

        let key = comparison_key(&excluded);
        let device = device_form(&key).expect("the temp drive has a device name");
        assert!(settings.is_excluded(Path::new(&format!(r"{device}\OUT.obj"))));
        assert!(settings.is_excluded(Path::new(&format!(r"\\?\GLOBALROOT{device}\out.obj"))));
        assert!(settings.is_excluded(&excluded.join("x.obj")));
        assert!(!settings.is_excluded(Path::new(&format!(r"{device}-old\x.obj"))));
    }

    #[test]
    fn changing_exclusions_invalidates_the_resolved_keys() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let mut settings = Settings::default();
        assert!(!settings.is_excluded(&root.join("a")));
        settings.add_exclusion(root.clone());
        assert!(settings.is_excluded(&root.join("a")));
        settings.exclusions.clear();
        settings.validate();
        assert!(!settings.is_excluded(&root.join("a")));
    }
}
