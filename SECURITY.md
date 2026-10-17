# Security policy

blackshard runs a kernel driver and a service as SYSTEM, so a bug in it can be a way into the
machine it is meant to protect. Reports are very welcome.

## Reporting a vulnerability

Please report privately, through GitHub's
[private vulnerability reporting](https://github.com/carlosrmz009/blackshard/security/advisories/new),
not in a public issue. Include what you found, the build (`version.txt`, or the version shown in
the UI), and the steps to reproduce it.

You should hear back within a week. Fixes land on `main` and in the next testing build; the report
is published as an advisory once a fixed build is out, crediting you unless you would rather not be
named.

## Scope

Everything in this repository is in scope. These matter most:

- the minifilter driver (`src/driver/`) and its communication port
- the local control pipes and how the service decides which clients to trust (`src/ipc.rs`,
  `src/trust.rs`)
- quarantine and restore (`src/quarantine.rs`)
- definition and update verification (`src/updater.rs`, `src/update_client.rs`,
  `src/definitions.rs`, `src/clamdb/`)
- the AMSI provider (`blackshard-amsi/`), which runs inside other processes
- the installers and their scripts (`install.ps1`, `installer/`)

Detection gaps, meaning malware blackshard does not catch, are worth reporting too, but can go in a
normal issue unless the sample itself is sensitive.

## Supported versions

blackshard is pre-release. Only the latest build from `main` receives fixes.
