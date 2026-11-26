# Changelog

blackshard is pre-release; every commit to `main` is published as the
[testing build](https://github.com/carl0srmz/blackshard/releases/tag/veryveryunstable). Notable
changes are listed here, newest first.

## Unreleased

### Security
- blackshard also starts in Safe Mode (with and without networking), so rebooting into Safe Mode
  no longer gets around it, and those Safe Mode entries are protected like its service keys.
- More ways of destroying a protected document now count as modifications, and the original is
  copied to the rollback vault first: opening it with truncation (overwrite or supersede),
  shrinking it through its end of file or allocation size, mapping it for writing, opening it
  delete-on-close, and giving it a hard link. Edits through a mapped view also invalidate cached
  verdicts for the file.
- The driver now reports every process start (image, command line, parent and creating process)
  and every DLL load to the service. A process whose image is detected is refused at creation,
  process starts are logged with their command lines, and ransomware alerts name how the
  offending program was started.
- The driver protects itself and the service: `fltmc unload` and `sc stop blackshard` fail, other
  processes (administrators included) can no longer terminate, suspend or inject into the service,
  and the driver's and service's registry keys can only be changed after the service was stopped
  on purpose. Updating or removing the driver now takes effect at the next restart.
- Once real-time protection has been ready, a program the service cannot judge in time (hung,
  crashed or killed service, bad reply) is blocked instead of allowed, unless it lives in Windows'
  own folders or Program Files. The driver waits up to 30 s for an execution verdict instead of
  1.5 s. Stopping the service through the service manager still turns enforcement off.
- A protected document write now waits up to 5 s for the service to copy the original to the
  rollback vault, instead of 0.1 s, so the copy is no longer racing the write it should precede.
- The CI auto-repair job no longer trusts branch names coming back from the job that ran the
  failed commit's code; it re-reads them from the run and only pushes to `autofix/` branches.
- Turbo freezes and repairs only once per administrator-approved pause, from a baseline taken when
  that pause began. A later turbo, by anyone, can no longer write an old boot record or registry
  value back.
- Files that deny SYSTEM read access are scanned anyway (backup semantics). An unsigned program
  that still cannot be scanned, or that changes or is swapped mid-scan, is not allowed to run.
- Windows' own catalog-signed binaries are recognised as signed, and revoked certificates are
  refused when Windows has the revocation data cached.
- Only programs directly in `C:\Windows`, `System32` or `SysWOW64` are spared as system
  processes. Malware named `svchost.exe` in a user-writable Windows folder is not.
- A program convicted only by ransomware-like behaviour is quarantined and blocklisted
  automatically only if it lives somewhere a user or download can put it, not under Program Files.
- Exclusions are shown only to administrators. A standard user's UI can still add one, which is
  added to the list instead of replacing it.
- A standard user's scan skips other people's profiles, so it cannot list their files.
- The elevated helper says what it is about to do (settings changes, quarantine restore or
  delete, clearing the history) in its own window and waits for a click, so a reused
  administrator prompt cannot quietly turn protection off.
- AMSI detections no longer record names chosen by the submitting program as verified paths, and
  each user's detections are limited to 20 history entries a minute. With the service down,
  scripts no longer each wait three seconds. Scripts over 4 MB are read at both ends.
- The control pipe takes four connections, so one client cannot keep the UI out.
- The service keeps protecting when another process has taken its pipe name, and retries the pipe.
  It now restarts after every failure, not just the first two.
- AMSI no longer treats scripts over ~1.1 MB as clean, and no longer rescans the service's own
  submissions.
- Quarantine restore refuses folders redirected by a junction or link.
- Cached clean verdicts are tied to the file's change time, so a same-size overwrite is rescanned.
- ClamAV definitions can no longer be rolled back to an older, still-signed version.
- Settings, history and learned shards moved to the administrator-only `State` folder.
- The CI auto-repair job no longer runs branch code next to a token that can write.
- The development installer's payload folder can no longer be pre-created by a standard user, and
  test-signing no longer leaves a code-signing key on the machine.
- Self-tests are administrator-only and rate-limited; clearing the history is recorded.

### Added
- Browser credential stores (Chromium's Login Data, Cookies, Web Data and Local State, Firefox's
  logins.json, key4.db and cookies.sqlite) can only be opened by the browser or a signed program;
  an infostealer is refused, stopped and removed.
- Rules for credential dumping (comsvcs MiniDump, procdump of lsass, saving the SAM and SECURITY
  hives), starting programs on other computers (remote WMIC, sc, schtasks, PsExec, winrs),
  rundll32 running a disguised file (NotPetya's perfc.dat) and browsers started with a user-folder
  extension or hidden remote debugging. Hidden unsigned programs on removable drives are blocked.
- The memory hunt detects process hollowing. Turbo also finds processes hidden from the process
  list, scans loaded kernel drivers (disabling and quarantining malicious ones), removes program
  images and loader scripts stored in users' registry hives, and reports attack tools' default
  pipe names.
- The rollback vault keeps up to 2,048 files and 1 GB per program, 4 GB in all.
- Program starts are judged by their command line: shadow-copy, backup and recovery deletion,
  Safe Mode reboots, tampering with blackshard, Defender or the firewall, launch and sign-in
  hijacks, download-and-run and in-memory loader PowerShell (also encoded), mshta, rundll32 and
  regsvr32 script proxies, quiet remote installs, certutil and bitsadmin downloads, Office
  starting a shell, scripts run from Downloads or archives, and AutoIt loaders. For ransomware and
  tampering rules, the program behind the command is stopped and removed too.
- Hidden decoy documents in each user's Documents and Pictures convict the first untrusted
  program that touches one, however slowly it encrypts.
- Turbo also reads the memory of running programs for code no file backs (Cobalt Strike, Sliver,
  Meterpreter, unpacked stealers), stopping the process or, in Windows' own, the injected threads;
  scans the boot record and the EFI system partition for bootkits; and removes autostarts the
  command-line rules condemn, from Run keys, tasks, services, BITS jobs and WMI subscriptions.
- Removing a program also cleans AppInit DLLs, Winlogon, IFEO and silent-exit hijacks, per-user
  COM hijacks, Active Setup, BITS jobs and WMI subscriptions. A removed Windows file is put back
  by the System File Checker.
- The pause baseline covers whole registry trees: Defender policies and exclusions, browser
  policies, root certificates, Safe Mode, IFEO, LSA packages, firewall rules for user-writable
  programs, proxy settings and the registrations UAC bypasses use.
- DLL side-loading next to a signed program, and suspicious unsigned downloads, are blocked at
  execution.
- Ctrl+Alt+Shift+T starts turbo from anywhere on the desktop.
- Ransomware protection covers Downloads and more document, photo and media types.
- The installer turns on Microsoft's vulnerable driver blocklist and, on Windows 11 22H2 and
  later, LSA protection (`-SkipSystemHardening` to leave them).
- Turbo also scans ProgramData, all of local AppData, `C:\Windows\Temp`, and the DLLs loaded
  into running programs. It puts back the hosts file, and cleans the Group Policy Run key.
- An option to also catch adware and other potentially unwanted programs.
- Real-time protection can be paused for 1, 5 or 15 minutes from the status page. It comes back
  on by itself and starts a turbo hunt; scripts through AMSI are not checked meanwhile either.
  Pausing asks for administrator approval; ending a pause with turbo does not.
- Turbo freezes every unsigned program started during the pause the moment it starts, kills
  convicted programs only after suspending all their copies, and clears the critical-process flag
  malware sets on itself, so watchdog malware cannot crash Windows as it is removed.
- Turbo puts back what changed since the pause began: the boot record (unless the disk was
  repartitioned), Task Manager, regedit and command prompt lock-outs, Winlogon shell hijacks,
  debugger hijacks, UAC and the wallpaper, and the documents a convicted program changed.
- HTML applications (`.hta`) that create a scripting object next to a command, download or run
  call are flagged.
- RTF documents are read for embedded objects: self-updating linked objects, Equation Editor
  objects, and embedded executables or Office files.
- Windows shortcuts (`.lnk`) are read: one that starts a script interpreter or downloader with
  arguments that fetch, decode or run code, or whose arguments are padded with blanks to hide the
  command, is flagged.
- ClamAV body signatures (`.ndb`) and logical signatures (`.ldb`) are matched natively: about
  399,000 of the 414,000 in the live databases, including entry-point and section offsets,
  match counts, file-size conditions and the `i`, `w`, `a` and `f` modifiers. Anything the
  matcher does not model (regular expressions, macros, alternatives, container conditions) is
  skipped whole and counted by reason in `--update-definitions`.
- Scanning against all of those signatures runs at about 35 MiB/s on a CI runner (it was 14),
  because identical pieces are shared between signatures and counted once.
- Before an unknown program changes a document, a copy is kept; if the program is convicted of
  ransomware the originals are restored.
- Removing a program also removes scheduled tasks, services and Startup-folder items that launch it.
- CI scans a few thousand clean Windows and developer-tool files, with and without the live
  ClamAV signatures, and fails on any detection; it also fails on driver analyzer findings.

### Fixed
- Document rollback never saved anything: it was handed kernel device paths Win32 cannot open.
  The folder pin is now also held for the whole restore.
- The boot-record backup covers the whole GPT partition-entry array.
- Registry repair never deletes a value it could not read, reads values over 64 KiB, and covers
  Microsoft Entra accounts, the 32-bit Winlogon key and program file associations.
- Services, tasks and startup items are removed only when they name the convicted file as a whole
  path, not as part of a longer one. Services hosted in svchost are matched by their DLL.
- The pause countdown appears only once the service has the pause, and turbo waits for a running
  scan to stop instead of being dropped.
- Toggling adware detection reloads signatures without stalling the service.
- 16-bit Windows executables and system DLLs are no longer flagged as malformed or as Office macros.
- Large valid executables and large ordinary archives are no longer flagged Suspicious.
- Every member of a multi-member gzip file is scanned.
- New definition generations are no longer lost when the service is busy.
- The UI opens without a console window.

### Changed
- The service logs to `State\logs\service.log`.
- The update channel can use TLS 1.3.
- Rust is pinned in `rust-toolchain.toml`; Dependabot proposes new releases.
