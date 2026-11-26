//! Decoy documents that only ransomware touches.
//!
//! The ransomware heuristic counts how many documents a program changes; a slow or intermittent
//! encryptor (Play, Royal) can stay under any count. A decoy no person opens does not have that
//! weakness: the first time a program that is not signed by a trusted publisher writes, renames
//! or deletes one, it is convicted.
//!
//! Each machine gets its own decoy names, random and kept in the administrator-only `State`
//! folder, so malware cannot learn a fixed list and skip them. They are hidden, sit where
//! ransomware starts (each user's Documents and Pictures) and are named to sort first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static DECOYS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// A decoy file name from 32 random bits: it sorts before ordinary names and reads like an
/// ordinary document.
pub fn decoy_name(random: u32, index: usize) -> String {
    const STEMS: [&str; 4] = [
        "budget summary",
        "tax return copy",
        "passport scan",
        "family photos index",
    ];
    const EXTENSIONS: [&str; 4] = ["docx", "xlsx", "pdf", "docx"];
    format!(
        "0{random:08x} {}.{}",
        STEMS[index % STEMS.len()],
        EXTENSIONS[index % EXTENSIONS.len()]
    )
}

fn key(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_ascii_lowercase()
}

/// Whether `path` is one of this machine's decoys.
pub fn is_decoy(path: &Path) -> bool {
    DECOYS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|decoys| decoys.contains(&key(path)))
}

fn remember(paths: &[PathBuf]) {
    *DECOYS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some(paths.iter().map(|path| key(path)).collect());
}

/// Puts this machine's decoys in place in each user's Documents and Pictures, creating names the
/// first time and recreating any that were removed. Called when the service starts and now and
/// then after.
#[cfg(windows)]
pub fn plant() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;

    let store = crate::paths::state_dir().join("decoys.json");
    let mut names: Vec<String> = std::fs::read(&store)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    if names.is_empty() {
        let random: u32 = rand::random();
        names = (0..2).map(|index| decoy_name(random, index)).collect();
        if let Ok(bytes) = serde_json::to_vec(&names) {
            let _ = crate::atomic_file::write(&store, &bytes);
        }
    }
    let mut decoys = Vec::new();
    for (_, profile) in crate::persistence::user_profiles() {
        for (folder, name) in ["Documents", "Pictures"].iter().zip(names.iter().cycle()) {
            let folder = profile.join(folder);
            if !folder.is_dir() {
                continue;
            }
            let path = folder.join(name);
            if !path.exists() {
                let created = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .attributes(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
                    .open(&path)
                    .and_then(|mut file| {
                        use std::io::Write;
                        let text = format!("{name}\r\n").repeat(400);
                        file.write_all(text.as_bytes())
                    });
                if let Err(error) = created {
                    log::warn!("Could not place a ransomware decoy at {path:?}: {error}");
                    continue;
                }
            }
            decoys.push(path);
        }
    }
    remember(&decoys);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_names_sort_first_and_look_like_documents() {
        let name = decoy_name(0x1a2b_3c4d, 0);
        assert_eq!(name, "01a2b3c4d budget summary.docx");
        assert!(name.as_str() < "Annual report.docx");
        assert!(decoy_name(7, 1).ends_with(".xlsx"));
    }

    #[test]
    fn decoys_are_recognised_whatever_the_path_form() {
        remember(&[PathBuf::from(
            r"C:\Users\x\Documents\0abc budget summary.docx",
        )]);
        assert!(is_decoy(Path::new(
            r"\\?\C:\Users\x\Documents\0ABC Budget Summary.docx"
        )));
        assert!(!is_decoy(Path::new(r"C:\Users\x\Documents\report.docx")));
    }
}
