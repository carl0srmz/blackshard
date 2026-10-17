//! Where blackshard keeps its machine-wide data.
//!
//! `ProgramData\blackshard` itself is readable by every user, because the UI and the definition
//! store are. Anything that says where blackshard does not look (exclusions), or what it found in
//! other people's profiles (history), lives in `State`, which install.ps1 restricts to SYSTEM and
//! administrators. The service reads it there and hands each client only what it may see.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// `ProgramData\blackshard`.
pub fn data_root() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("blackshard")
}

/// `ProgramData\blackshard\State`, readable only by SYSTEM and administrators.
pub fn state_dir() -> PathBuf {
    data_root().join("State")
}

/// Files earlier builds kept in the readable data root, which now belong in `State`.
pub const FILES_MOVED_TO_STATE: [&str; 4] = [
    "settings.json",
    "history.jsonl",
    "history.jsonl.1",
    "shards.json",
];

/// Moves each of `names` from `old_root` into `state`, once, at service start.
///
/// A file already in `state` wins: it is the one this build has been writing, and the copy in the
/// old root is a leftover that would otherwise stay readable by every user. Returns the names that
/// were moved.
pub fn migrate_into_state(
    old_root: &Path,
    state: &Path,
    names: &[&str],
) -> io::Result<Vec<String>> {
    fs::create_dir_all(state)?;
    let mut moved = Vec::new();
    for name in names {
        let old = old_root.join(name);
        match fs::symlink_metadata(&old) {
            Ok(metadata) if metadata.is_file() => {}
            // Absent, or something this code did not create; leave it for a person to look at.
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let new = state.join(name);
        if new.exists() {
            fs::remove_file(&old)?;
        } else {
            fs::rename(&old, &new)?;
            moved.push((*name).to_owned());
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_files_move_into_state_once() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let state = root.join("State");
        fs::write(root.join("settings.json"), b"old settings").unwrap();
        fs::write(root.join("history.jsonl"), b"old history").unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("history.jsonl"), b"current history").unwrap();

        let moved = migrate_into_state(root, &state, &FILES_MOVED_TO_STATE).unwrap();

        assert_eq!(moved, ["settings.json"]);
        assert_eq!(
            fs::read(state.join("settings.json")).unwrap(),
            b"old settings"
        );
        // The copy in State is the live one; the readable leftover is dropped, not merged.
        assert_eq!(
            fs::read(state.join("history.jsonl")).unwrap(),
            b"current history"
        );
        assert!(!root.join("settings.json").exists());
        assert!(!root.join("history.jsonl").exists());

        // Nothing left to do the second time.
        assert!(migrate_into_state(root, &state, &FILES_MOVED_TO_STATE)
            .unwrap()
            .is_empty());
    }
}
