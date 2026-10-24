//! Windows shortcuts (`.lnk`, "Shell Link" files).
//!
//! A shortcut is a document that launches a program, which makes it a favourite way to start a
//! script interpreter from an attachment or an archive. Only the parts that say what will be run
//! are read: the target (from the link info, or the relative path) and the command-line
//! arguments. Every length comes from the file, so every read is bounds-checked.

const HEADER_SIZE: usize = 0x4c;
const SHELL_LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

const HAS_TARGET_ID_LIST: u32 = 1 << 0;
const HAS_LINK_INFO: u32 = 1 << 1;
const HAS_NAME: u32 = 1 << 2;
const HAS_RELATIVE_PATH: u32 = 1 << 3;
const HAS_WORKING_DIR: u32 = 1 << 4;
const HAS_ARGUMENTS: u32 = 1 << 5;
const HAS_ICON_LOCATION: u32 = 1 << 6;
const IS_UNICODE: u32 = 1 << 7;

/// `SW_SHOWMINNOACTIVE`, `SW_SHOWMINIMIZED`: the window the shortcut opens is not shown.
const SHOW_MINIMIZED: [u32; 2] = [2, 7];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Shortcut {
    /// The program the shortcut starts, as written in the file.
    pub target: String,
    pub arguments: String,
    pub minimized: bool,
}

pub fn is_shortcut(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_SIZE
        && bytes.starts_with(&(HEADER_SIZE as u32).to_le_bytes())
        && bytes[4..20] == SHELL_LINK_CLSID
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(length)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    /// A counted string; the count is in characters.
    fn string(&mut self, unicode: bool) -> Option<String> {
        let characters = usize::from(self.u16()?);
        if unicode {
            let raw = self.take(characters * 2)?;
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            Some(String::from_utf16_lossy(&units))
        } else {
            Some(
                self.take(characters)?
                    .iter()
                    .map(|&byte| char::from(byte))
                    .collect(),
            )
        }
    }
}

/// The local path from a link-info block, if it has one.
fn local_base_path(info: &[u8]) -> Option<String> {
    let flags = u32::from_le_bytes(info.get(8..12)?.try_into().ok()?);
    if flags & 1 == 0 {
        return None;
    }
    let offset = u32::from_le_bytes(info.get(16..20)?.try_into().ok()?) as usize;
    let tail = info.get(offset..)?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(tail.len());
    Some(tail[..end].iter().map(|&byte| char::from(byte)).collect())
}

pub fn parse(bytes: &[u8]) -> Option<Shortcut> {
    if !is_shortcut(bytes) {
        return None;
    }
    let flags = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let show = u32::from_le_bytes(bytes[60..64].try_into().ok()?);
    let mut cursor = Cursor {
        bytes,
        at: HEADER_SIZE,
    };

    if flags & HAS_TARGET_ID_LIST != 0 {
        let size = usize::from(cursor.u16()?);
        cursor.take(size)?;
    }
    let mut target = String::new();
    if flags & HAS_LINK_INFO != 0 {
        let start = cursor.at;
        let size = cursor.u32()? as usize;
        let info = bytes.get(start..start.checked_add(size)?)?;
        cursor.at = start + size;
        target = local_base_path(info).unwrap_or_default();
    }

    let unicode = flags & IS_UNICODE != 0;
    if flags & HAS_NAME != 0 {
        cursor.string(unicode)?;
    }
    let relative = if flags & HAS_RELATIVE_PATH != 0 {
        cursor.string(unicode)?
    } else {
        String::new()
    };
    if flags & HAS_WORKING_DIR != 0 {
        cursor.string(unicode)?;
    }
    let arguments = if flags & HAS_ARGUMENTS != 0 {
        cursor.string(unicode)?
    } else {
        String::new()
    };
    if flags & HAS_ICON_LOCATION != 0 {
        cursor.string(unicode).unwrap_or_default();
    }

    if target.is_empty() {
        target = relative;
    }
    Some(Shortcut {
        target,
        arguments,
        minimized: SHOW_MINIMIZED.contains(&show),
    })
}

#[cfg(test)]
pub(crate) fn build(target: &str, arguments: &str, show: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    bytes.extend_from_slice(&SHELL_LINK_CLSID);
    let flags = HAS_RELATIVE_PATH | HAS_ARGUMENTS | IS_UNICODE;
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.resize(60, 0);
    bytes.extend_from_slice(&show.to_le_bytes());
    bytes.resize(HEADER_SIZE, 0);
    for text in [target, arguments] {
        let units: Vec<u16> = text.encode_utf16().collect();
        bytes.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for unit in units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_target_arguments_and_window() {
        let bytes = build(r"..\..\Windows\System32\cmd.exe", "/c calc", 7);
        let shortcut = parse(&bytes).expect("a valid shortcut");
        assert_eq!(shortcut.target, r"..\..\Windows\System32\cmd.exe");
        assert_eq!(shortcut.arguments, "/c calc");
        assert!(shortcut.minimized);
        assert!(!parse(&build("a.exe", "", 1)).unwrap().minimized);
    }

    #[test]
    fn damaged_shortcuts_are_refused_not_trusted() {
        let bytes = build("cmd.exe", "/c echo hi", 1);
        for length in 0..bytes.len() {
            // Must not panic; a cut-off file either parses what is there or is refused.
            let _ = parse(&bytes[..length]);
        }
        assert!(parse(b"MZ not a shortcut").is_none());
        let mut lying = bytes.clone();
        lying[HEADER_SIZE] = 0xff;
        lying[HEADER_SIZE + 1] = 0xff;
        assert!(parse(&lying).is_none());
    }
}
