# Changelog

blackshard is pre-release; every commit to `main` is published as the
[testing build](https://github.com/carl0srmz/blackshard/releases/tag/veryveryunstable). Notable
changes are listed here, newest first.

## Unreleased

### Security
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
- 16-bit Windows executables and system DLLs are no longer flagged as malformed or as Office macros.
- Large valid executables and large ordinary archives are no longer flagged Suspicious.
- Every member of a multi-member gzip file is scanned.
- New definition generations are no longer lost when the service is busy.
- The UI opens without a console window.

### Changed
- The service logs to `State\logs\service.log`.
- The update channel can use TLS 1.3.
- Rust is pinned in `rust-toolchain.toml`; Dependabot proposes new releases.
