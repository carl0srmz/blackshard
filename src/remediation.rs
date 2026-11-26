//! The parts of cleaning up after a removed program that need no Windows API.
//!
//! Malware that is quarantined usually leaves something behind that would start it again. The
//! functions here read what a scheduled task would run; `persistence` does the rest.

/// Everything a scheduled task's definition would launch, as one command line per action: the
/// `<Command>` and `<Arguments>` of each `<Exec>`. Task files are UTF-16 with a byte order mark as
/// Windows writes them, or UTF-8 when something else did.
pub fn task_command_lines(definition: &[u8]) -> Vec<String> {
    let text = decode_text(definition);
    let mut lines = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = find_tag(rest, "<Exec") {
        let after = &rest[start..];
        let end = find_tag(after, "</Exec>").unwrap_or(after.len());
        let exec = &after[..end];
        let command = element(exec, "Command").unwrap_or_default();
        let arguments = element(exec, "Arguments").unwrap_or_default();
        if !command.is_empty() || !arguments.is_empty() {
            lines.push(format!("{command} {arguments}").trim().to_owned());
        }
        rest = &after[end.max(1).min(after.len())..];
    }
    lines
}

/// Whether a startup-folder item (a `.lnk` shortcut, or a `.bat`/`.cmd`/`.vbs`/`.url` script)
/// names `target`. Shortcuts keep the target as ANSI and as UTF-16, scripts as plain text, so both
/// encodings are searched, ignoring case. `target` must be a full path with at least a folder.
pub fn item_launches(item: &[u8], target: &str) -> bool {
    if target.len() < 4 || !target.contains('\\') {
        return false;
    }
    let ascii = target.to_ascii_lowercase();
    let wide: Vec<u8> = ascii.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let lowered = item.to_ascii_lowercase();
    // UTF-16 text has a zero after every ASCII letter, so lowering bytes lowers it as well.
    contains(&lowered, ascii.as_bytes()) || contains(&lowered, &wide)
}

/// Whether a command line names `target` as a whole path, not as the start of a longer one:
/// `c:\tools\x.exe` is in `"c:\tools\x.exe" /run` and `rundll32 c:\tools\x.exe,go`, but not in
/// `c:\tools\x.exe.bak` or `c:\tools\x.exe-helper.exe`. Both arguments are already lower case.
/// Removing a service or task on a looser match could delete another program's.
pub fn command_names_path(command: &str, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let separates = |character: Option<char>| {
        character.is_none_or(|character| {
            matches!(
                character,
                '"' | '\'' | ' ' | '\t' | ',' | '=' | '(' | ')' | ';'
            )
        })
    };
    command.match_indices(target).any(|(start, _)| {
        separates(command[..start].chars().next_back())
            && separates(command[start + target.len()..].chars().next())
    })
}

/// What a registry value holds that no program keeps in the registry: a whole program image, raw
/// or as base64 (Ursnif, Kovter), or script that downloads and runs code or starts programs
/// (Poweliks, Kovter's JavaScript). Fileless malware keeps its real code in values like these and
/// only a small launcher in a Run key. `kind` is the registry type; small values are not looked at.
pub fn registry_payload(kind: u32, data: &[u8]) -> Option<&'static str> {
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_MULTI_SZ: u32 = 7;
    if data.len() < 1024 {
        return None;
    }
    if kind == REG_BINARY && crate::memory_scan::looks_like_loaded_image(data) {
        return Some("a program image");
    }
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ | REG_BINARY) {
        return None;
    }
    // Registry strings are UTF-16LE; binary values holding text may be either.
    let wide: String = String::from_utf16_lossy(
        &data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>(),
    );
    let narrow = String::from_utf8_lossy(data);
    for text in [wide.as_str(), narrow.as_ref()] {
        let trimmed = text.trim_matches(char::from(0)).trim();
        // "TVqQ", "TVpQ", "TVoA": base64 of an MZ header.
        if ["TVqQ", "TVpQ", "TVoA", "TVro"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            use base64::Engine;
            let encoded: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if base64::engine::general_purpose::STANDARD
                .decode(encoded.trim_end_matches(char::from(0)))
                .is_ok_and(|decoded| crate::memory_scan::looks_like_loaded_image(&decoded))
            {
                return Some("a program image in base64");
            }
        }
        if crate::command_rules::judge_script(&trimmed.to_ascii_lowercase()).is_some() {
            return Some("a loader script");
        }
    }
    None
}

/// A BITS job and the command it runs when it finishes, from `bitsadmin /list /verbose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitsJob {
    pub guid: String,
    pub notify_command: String,
}

/// Reads the jobs that have a completion command out of `bitsadmin /list /allusers /verbose`.
/// The command is printed as `'program' 'arguments'`.
pub fn bits_jobs(listing: &str) -> Vec<BitsJob> {
    let mut jobs = Vec::new();
    let mut guid: Option<String> = None;
    for line in listing.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("GUID:") {
            guid = rest
                .find('{')
                .and_then(|start| {
                    rest[start..]
                        .find('}')
                        .map(|end| &rest[start..start + end + 1])
                })
                .map(str::to_owned);
        } else if let Some(rest) = line.strip_prefix("NOTIFICATION COMMAND LINE:") {
            let command = rest.trim();
            if command.is_empty() || command.eq_ignore_ascii_case("none") {
                continue;
            }
            let command = command
                .split('\'')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(guid) = &guid {
                jobs.push(BitsJob {
                    guid: guid.clone(),
                    notify_command: command,
                });
            }
        }
    }
    jobs
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        other => String::from_utf8_lossy(other).into_owned(),
    }
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| unit(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The byte offset of `tag` in `text`, ignoring case. Tags have only ASCII letters, so lowering
/// the haystack leaves every offset where it was.
fn find_tag(text: &str, tag: &str) -> Option<usize> {
    text.to_ascii_lowercase().find(&tag.to_ascii_lowercase())
}

/// The text inside the first `<name>…</name>` of `xml`, with entities decoded.
fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = find_tag(xml, &open)? + open.len();
    let end = start + find_tag(&xml[start..], &format!("</{name}>"))?;
    Some(decode_entities(xml[start..end].trim()))
}

fn decode_entities(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        // Last, so "&amp;lt;" decodes to "&lt;" and not "<".
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_image() -> Vec<u8> {
        let mut bytes = vec![0u8; 2048];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn programs_and_loader_scripts_stored_in_the_registry_are_found() {
        use base64::Engine;
        assert_eq!(
            registry_payload(3, &program_image()),
            Some("a program image")
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(program_image());
        assert_eq!(
            registry_payload(1, &utf16(&encoded)),
            Some("a program image in base64")
        );
        let script = format!(
            "var s = new ActiveXObject('WScript.Shell'); s.Run('mshta ...');{}",
            " ".repeat(1200)
        );
        assert_eq!(
            registry_payload(1, &utf16(&script)),
            Some("a loader script")
        );
        assert_eq!(
            registry_payload(1, &utf16(&"ordinary settings ".repeat(100))),
            None
        );
        assert_eq!(registry_payload(3, &[0u8; 4096]), None);
        assert_eq!(
            registry_payload(3, b"MZ tiny"),
            None,
            "too small to look at"
        );
    }

    #[test]
    fn bits_jobs_with_a_completion_command_are_read() {
        let listing = "GUID: {6F1C1D2A-0000-4000-8000-000000000001} DISPLAY: 'update'
TYPE: DOWNLOAD STATE: TRANSFERRED OWNER: PC\\x
NOTIFICATION COMMAND LINE: 'C:\\Windows\\System32\\cmd.exe' '/c C:\\Users\\x\\a.exe'
GUID: {6F1C1D2A-0000-4000-8000-000000000002} DISPLAY: 'plain'
NOTIFICATION COMMAND LINE: none
";
        assert_eq!(
            bits_jobs(listing),
            vec![BitsJob {
                guid: "{6F1C1D2A-0000-4000-8000-000000000001}".to_owned(),
                notify_command: r"C:\Windows\System32\cmd.exe /c C:\Users\x\a.exe".to_owned(),
            }]
        );
    }

    #[test]
    fn a_command_names_a_path_only_as_a_whole() {
        let target = r"c:\tools\x.exe";
        assert!(command_names_path(r"c:\tools\x.exe", target));
        assert!(command_names_path(r#""c:\tools\x.exe" /run"#, target));
        assert!(command_names_path(
            r"rundll32.exe c:\tools\x.exe,go",
            target
        ));
        assert!(command_names_path(r"cmd /c start c:\tools\x.exe", target));
        assert!(!command_names_path(r"c:\tools\x.exe.bak", target));
        assert!(!command_names_path(r"c:\tools\x.exe-helper.exe /s", target));
        assert!(!command_names_path(r"c:\tools\x.exe2", target));
        assert!(!command_names_path("", target));
    }

    const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\alice\AppData\Roaming\evil\evil.exe</Command>
      <Arguments>--hidden &amp;&amp; &quot;x&quot;</Arguments>
    </Exec>
    <exec>
      <command>"%APPDATA%\second.exe"</command>
    </exec>
  </Actions>
</Task>"#;

    #[test]
    fn every_action_of_a_task_is_read() {
        let lines = task_command_lines(TASK.as_bytes());
        assert_eq!(
            lines,
            [
                r#"C:\Users\alice\AppData\Roaming\evil\evil.exe --hidden && "x""#,
                r#""%APPDATA%\second.exe""#,
            ]
        );
    }

    #[test]
    fn utf16_task_files_are_read_as_windows_writes_them() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in TASK.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(task_command_lines(&bytes).len(), 2);

        let mut big_endian = vec![0xFE, 0xFF];
        for unit in TASK.encode_utf16() {
            big_endian.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(task_command_lines(&big_endian).len(), 2);
    }

    #[test]
    fn tasks_without_commands_and_garbage_yield_nothing() {
        assert!(task_command_lines(b"<Task><Actions/></Task>").is_empty());
        assert!(task_command_lines(b"").is_empty());
        assert!(task_command_lines(&[0xFF, 0xFE, 0x00]).is_empty());
        assert!(task_command_lines(b"<Exec><Command>unterminated").is_empty());
        assert!(task_command_lines(b"<Exec><Exec><Exec>").is_empty());
    }

    #[test]
    fn startup_items_are_matched_in_both_encodings() {
        let target = r"C:\Users\Alice\AppData\Roaming\evil\Evil.exe";
        let wide: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut shortcut = b"L\0\0\0junk".to_vec();
        shortcut.extend_from_slice(&wide);
        assert!(item_launches(&shortcut, &target.to_lowercase()));
        let script = format!("@echo off\r\nstart \"\" \"{}\"", target.to_uppercase());
        assert!(item_launches(script.as_bytes(), target));
        assert!(!item_launches(b"start notepad.exe", target));
        assert!(!item_launches(b"anything", "evil"));
        assert!(!item_launches(b"", target));
    }

    #[test]
    fn entities_decode_once() {
        assert_eq!(decode_entities("a &amp;lt; b"), "a &lt; b");
        assert_eq!(decode_entities("&lt;&gt;&quot;&apos;"), "<>\"'");
    }
}
