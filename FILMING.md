# blackshard vs. famous malware: filming runbook

For the series: let a show-off sample run for a bit, then end it with turbo and show everything put back.

**Warning:** these samples destroy machines. Only run them in a disposable VM, never on a machine you care about.

## One-time setup

### 1. Build (GitHub Actions is out until Dec 1, so build on Windows)

On a Windows 10/11 machine or VM that has the build tools from the README:

```powershell
rustup toolchain install          # the pinned 1.99.1 from rust-toolchain.toml
.\deploy.ps1                      # collects everything into dist\
cargo test --workspace --all-targets
```

`cargo test` here also runs the Windows-only tests that can't run on Linux. Copy `dist\` into the filming VM.

### 2. The filming VM

- **Windows 10, BIOS / "Generation 1".** On a UEFI/GPT VM, an MBR overwrite often doesn't stop
  Windows from booting, so the boot-record repair has nothing visible to show.
- **Secure Boot off.** Turn off shared clipboard, drag and drop, and shared folders once the files
  are copied in.
- Inside the VM, as administrator, run `.\enable-test-signing.ps1` and reboot. Then run
  `.\install.ps1 -AllowUnsigned`. Install **with** the driver: without it, protection is only the
  script scanner (AMSI) and `.exe` samples simply run.
- Open blackshard and wait until the status page is green and the definitions have downloaded.
  That needs internet.
- **Cut the VM's network.** The samples don't need it.

### 3. Check each sample before filming

Copy the samples to `C:\samples`. Pause protection first (step 3 of the episode), or the driver
blocks them as you copy. Then, in an admin PowerShell:

```powershell
& "C:\Program Files\blackshard\blackshard-service.exe" --evaluate-corpus C:\samples C:\report.json "C:\ProgramData\blackshard\ClamAV\Generations\<newest folder>"
```

`report.json` lists each file as clean, suspicious or malicious. It does not include the
adware (PUA) signatures; for BonziBuddy-style samples, turn on "also catch adware" in settings
and test with a real take. **A file marked clean will not be
caught.** It gets frozen when turbo starts and resumed when the hunt ends, so it keeps running. Either film that as a loss, or skip it.

### 4. Snapshot

Take a VM snapshot named `ready`: blackshard green, network off, samples on the Desktop. Revert to
it before every take.

## Each episode

1. **Revert to `ready`** and open blackshard on the status page. Right-click it and choose "Run as
   administrator" if you don't want prompts on camera when you pause. Run normally, a pause asks
   twice: the Windows administrator prompt, then blackshard's own "go ahead?" window naming the
   change. Running as administrator also shows the full exclusion list.
2. **Optional opening shot:** double-click the sample while protection is on. blackshard blocks it
   before it starts.
3. **Pause:** on the status page, click `[5 min]` next to "pause protection for" and approve the
   prompt(s). The countdown appears once the service has the pause. At that moment blackshard records the boot record and the
   registry values malware likes to change, and from then on it copies documents before unknown
   programs change them. Only the turbo that ends this pause freezes and repairs, so don't
   restart the service or start another turbo in between.
4. **Run the sample** from the Desktop. Let it play for 30–90 s. The countdown is your safety net:
   when it runs out, protection comes back and the hunt starts by itself.
5. **Turbo**, any one of these:
   - `[resume and hunt now]` on the status page
   - **Ctrl+Shift+T** (the blackshard window must have focus)
   - triple-click the shard

   What happens:
   - Everything unsigned that started during the pause is suspended at once, and the desktop is
     repainted, so the effects stop instantly.
   - The hunt scans at full speed, kills convicted programs (all copies suspended first, so
     watchdogs can't crash Windows) and quarantines them.
   - It removes their autostarts, then puts back the boot record, the lock-out policies, Winlogon,
     debugger hijacks, UAC, the wallpaper, and the documents they changed.
   - The banner reads like: *"hunt over in 3.2 s. 6 threats stopped, removed and cleaned up.
     repaired: boot record of disk 0 restored; DisableTaskMgr put back; Wallpaper put back and 2 more."*
6. **Proof shots:** open Task Manager and regedit, show the desktop, then **reboot** to show it
   still boots. Open the quarantine and activity pages.
7. Revert to `ready` for the next take.

## Before the first real episode

None of this has run on Windows yet. The Windows code was type-checked with clippy from Linux,
and the logic tests pass, but nothing has run on a real machine. Do one full dry run off camera with MEMZ, and send the service log to Claude if anything misbehaves. The log is at `C:\ProgramData\blackshard\State\logs\service.log`.

## Known limits

- Detection is still signatures plus heuristics. Turbo can only remove what blackshard convicts.
  Bonzi-style adware is likely missed, because the PUA signatures are off.
- The boot record is left alone if the partition layout changed since the pause, so a repartitioned disk is never overwritten.
- Documents only come back if they were in your user folders, were changed by an unsigned
  program, and the driver was installed.
- A program that marked itself critical and lives inside `C:\Windows` is not killed. It stays
  suspended instead.
- If you sign in as another user after pausing, that user's registry has no snapshot and is not repaired.
