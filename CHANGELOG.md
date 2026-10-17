# Changelog

blackshard is pre-release; every commit to `main` is published as the
[testing build](https://github.com/carlosrmz009/blackshard/releases/tag/veryveryunstable). Notable
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

### Fixed
- Large valid executables and large ordinary archives are no longer flagged Suspicious.
- Every member of a multi-member gzip file is scanned.
- New definition generations are no longer lost when the service is busy.
- The UI opens without a console window.

### Changed
- The service logs to `State\logs\service.log`.
- The update channel can use TLS 1.3.
- Rust is pinned in `rust-toolchain.toml`; Dependabot proposes new releases.
