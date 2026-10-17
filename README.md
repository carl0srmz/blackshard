
![Logo](https://github.com/carlosrmz009/blackshard-site/blob/main/assets/logo_horizontal.png?raw=true)

open-source adaptive antivirus agent

[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://github.com/carlosrmz009/blackshard/blob/main/LICENSE)


## License

[GPL v3](https://github.com/carlosrmz009/blackshard/blob/main/LICENSE)


## Roadmap

<img width="1479" height="590" alt="image" src="https://github.com/user-attachments/assets/d48616a4-31f7-4e75-9754-6ea3f2c56010" />

#### Phase I

- windows client
- GUI
- P2P shardnet

#### Phase II

- linux / macOS clients
- legacy compatibility
- collaboration with commercial AVs (always open to talk, contact me!)


## Demo

blackshard is currently in really early stages of development, so no stable download is offered. If you're really brave, though, you can try compiling your own binaries, or grab `blackshard-setup.exe` from the [testing candidate](https://github.com/carlosrmz009/blackshard/releases/tag/veryveryunstable) release, rebuilt from every commit to main (NOT RECOMMENDED, NOT SIGNED AND UNSTABLE! try it in a VM).


## Architecture

```
            kernel                              user mode
 ┌─────────────────────────┐   filter port   ┌──────────────────────────────┐
 │ blackshard.sys          │ ──────────────► │ blackshard-service (SYSTEM)  │
 │ minifilter: opens,      │ ◄────────────── │ detection engine: hashes,    │
 │ image loads, writes,    │  allow / block  │ ClamAV databases, YARA-X,    │
 │ renames                 │                 │ similarity, learned shards   │
 └─────────────────────────┘                 │ quarantine, history, updates │
                                             └──────────────▲───────────────┘
 ┌─────────────────────────┐   AMSI pipe                    │ control pipe
 │ blackshard-amsi.dll     │ ───────────────────────────────┤
 │ inside PowerShell,      │                                │
 │ Office, and other hosts │                 ┌──────────────┴───────────────┐
 └─────────────────────────┘                 │ blackshard-ui (the user)     │
                                             └──────────────────────────────┘
```

- **the driver** sees every file a program opens, every image it maps, and writes and renames in
  user folders, and waits for the service's verdict before letting the operation through.
- **the service** does all the scanning, quarantines what it convicts, keeps the activity history,
  and downloads signed definition updates. Settings and history live in
  `ProgramData\blackshard\State`, which only administrators can read; the log is in
  `State\logs\service.log`.
- **the AMSI provider** hands scripts to the service right before they run, after the host has
  deobfuscated them.
- **the UI** talks to the service over a local pipe. The service checks that it is the genuine
  signed binary from the install folder, and changing settings needs an elevated helper.

Without the driver (`install.ps1 -SkipDriver`), real-time coverage comes from AMSI alone.


## Building from source

you'll need Windows 10/11 x64 with:

- **Visual Studio 2022 Build Tools** with the C++ workload. The driver also needs the **Windows
  Driver Kit**; if it isn't installed, `build-driver.ps1` downloads a pinned, hash-checked WDK
  package instead.
- **Rust** through [rustup](https://rustup.rs). The exact release, components and targets are
  pinned in `rust-toolchain.toml`, so `rustup toolchain install` in the repository sets
  everything up.

```powershell
.\deploy.ps1     # driver, service, UI and both AMSI providers, collected into dist\
cargo test --workspace --all-targets
```

`installer\build-development-vm-installer.ps1` wraps `dist\` into the single-file setup used for
the testing builds; it needs the .NET Framework C# compiler that ships with Windows.

the driver is test-signed, so installing it needs test-signing mode (`enable-test-signing.ps1`)
and Secure Boot off. please only do that in a VM.


## Security

found a vulnerability? please read [SECURITY.md](SECURITY.md) and report it privately.


## FAQ

### What is blackshard?

blackshard is a lightweight, efficient, and highly adaptive antivirus agent. currently, only a Windows 10/11 version is being developed, but other platforms are coming soon!

### How much does blackshard cost?

well, let's see...

free version - 0$ /
premium version - 0$ /
enterprise version - 0$ /
ultimate deluxe version - 0$

so yeah, it's free. forever.

### How do I install blackshard in my computer?

you can't. not yet. i'm working on it :)

jokes aside, please do not tell chatgpt to help you install it... IT WON'T WORK, and also you could break your computer :(

### How does it work?

standard antivirus software acts like a security guard at the front entrance. the guard carries a list of "wanted criminals" (known viruses). If someone on the list tries to walk in, the guard stops them and removes the threat. instead of standing at the front door, blackshard lives deep inside the brain of the computer (the kernel). Every single time any program touches, moves, or changes a file, blackshard sees it happen instantly. 

there's also something called shardnet. the next question talks about that, you should read that...

### What is "shardnet"?

shardnet is a prototype for a P2P (peer to peer), international network run by all of the people using blackshard. you don't have to do anything, when using blackshard, you are automatically contributing! so, what's the deal with it? you see...

imagine brand new malware (computer virus), never seen before, suddenly appears and starts infecting computers in Asia. in an infected host, blackshard automatically generates a signature (shard) by analyzing the new program's behaviour. this "shard" is then shared across the entire shardnet network. by the time the threat reaches another continent, the entire network will already be armed and expecting it. think of is as a vaccine brigade, just a really fast one.

