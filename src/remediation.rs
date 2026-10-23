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
        .chunks_exact(2)
        .map(|pair| unit([pair[0], pair[1]]))
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
    fn entities_decode_once() {
        assert_eq!(decode_entities("a &amp;lt; b"), "a &lt; b");
        assert_eq!(decode_entities("&lt;&gt;&quot;&apos;"), "<>\"'");
    }
}
