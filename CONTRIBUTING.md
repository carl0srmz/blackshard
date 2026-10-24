# Contributing to blackshard

thanks for wanting to help! a few things that make it easier.

## Before you start

- **security problems** go through [SECURITY.md](SECURITY.md), never a public issue or pull request.
- for anything bigger than a fix, open an issue first so we can agree on the approach.
- shardnet (the P2P part) is developed separately for now and will be merged later.

## Building and testing

see [Building from source](README.md#building-from-source). the product (service, driver, UI, AMSI)
builds and tests on Windows only. the detection engine, the definition pipeline and the signature
matcher are platform independent, so on Linux or macOS `cargo test --lib` runs their tests in
seconds, and `cargo clippy --lib -- -D warnings` checks them. everything Rust is pinned in
`rust-toolchain.toml`.

before opening a pull request, run what CI runs:

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CI (`security-ci`) also builds the driver and installer, then installs, upgrades and uninstalls
blackshard on a clean runner. if you touched the driver, say how you tested it: CI can't load an
unsigned driver, so that part needs a VM.

## Writing code here

- match the code around you: its naming, its error handling, and its comments, which explain *why*.
- the service runs as SYSTEM and the driver in the kernel. treat every path, pipe message and file
  from a user as hostile, bound every read, and fail closed.
- add a test for the behaviour you change, especially for security fixes.
- keep each commit to one change, with a message that says what was wrong and why the fix is
  right.

## License

by contributing you agree that your contribution is licensed under the [GPL v3](LICENSE).
