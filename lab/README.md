# blackshard filming lab (Hyper-V)

An isolated, disposable Windows 10 VM for the FILMING.md / GAUNTLET.md episodes. Live samples
run in it, so it is set up so nothing can reach your host, your LAN, or the internet while they
run.

## What keeps the samples in

| Layer | Isolated (samples) | Online (setup only) |
|---|---|---|
| Hyper-V switch | **Private**: no host adapter, no physical NIC. There's no route out. | Internal switch + WinNAT, internet only |
| Switch-port ACLs (on the host, out of the guest's reach) | deny 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, multicast, IPv6 ULA/link-local | same |
| Host firewall | n/a | blocks all inbound from the lab adapter and the 10.213.0.0/24 subnet |
| Guest firewall, IPv6 off, LLMNR/NetBIOS off | backup layer | backup layer |
| Host ↔ guest data paths | enhanced session (clipboard/drives) off, Guest Service Interface, KVP and VSS off, no shared folders | same |
| Files in | read-only payload ISO only | same |
| Files out | OUTBOX disk, read on the host read-only, text files only, VM off | same |
| Other | Gen 1/BIOS (MBR, per FILMING.md), no nested virtualization, doesn't auto-start with the host, Standard checkpoints (memory included) | |

**Rule:** samples are only unzipped and run in **Isolated** mode. Online mode is for Windows setup,
blackshard's definition download, and downloading samples while they're still in their encrypted ZIPs
(password `infected`). Mass-mailers and worms on Online mode would send real traffic from your
public IP. `Set-LabNetwork.ps1` refuses Online once a `ready` checkpoint exists, unless the VM is
running from `base`.

## New PC: one command

You'll need a Windows 10 22H2 x64 ISO (Microsoft's Media Creation Tool → "ISO file"). Windows 11 won't
install on a Gen 1 VM. Clone the repository, then in an **elevated** PowerShell in `lab\`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Setup-Lab.ps1 -WindowsIso D:\iso\Win10_22H2_English_x64.iso -Build
```

To walk away instead (for example while the ISO is still downloading), run
`.\Start-LabSetup.ps1 -WindowsIso <iso> -RestartAutomatically`. It waits for the download to finish,
runs Setup-Lab, restarts if Hyper-V needed enabling (after a 5-minute warning; `shutdown /a`
cancels it), and continues by itself when you sign back in.

On the first run it enables Hyper-V and asks for a restart. After that, run the same command again.
`-Build` runs `deploy.ps1` in the checkout that holds this `lab\` (Rust plus the VS 2022 C++ build
tools), and its `dist\` goes into the VM. Without `-Build`, an existing `dist\` is used. To use another
build, pass `-DistPath <dist>`, or add one later with `Update-LabPayload.ps1`. With no build at all,
the VM downloads the testing build from the `veryveryunstable` release on first boot, checks its
SHA256, and test-signs it (`guest\Get-BlackshardRelease.ps1`).

Windows installs unattended, signs in automatically, configures itself (`C:\lab\setup.log`),
test-signs the driver and restarts. The VM's local password is in `state\vm-credentials.txt`
(gitignored).

## Getting to `ready`

Inside the VM, `NEXT-STEPS.txt` on the Desktop has the same list:

1. Optional but recommended: in Windows Security, turn off **Tamper Protection**, then run
   `C:\lab\Disable-Defender.ps1` as admin. Defender then stays out of the episodes and uploads nothing.
2. `cd C:\blackshard-dist; .\install.ps1 -AllowUnsigned`, then restart.
3. Open blackshard and wait for green plus definitions.
4. `C:\lab\Test-Isolation.ps1` should show internet OK and host/LAN blocked.
5. Eject the Windows ISO so an MBR wipe really fails to boot, and take the clean checkpoint:
   ```powershell
   Set-VMDvdDrive -VMName blackshard-film -ControllerNumber 1 -ControllerLocation 0 -Path $null
   Checkpoint-VM -Name blackshard-film -SnapshotName base
   ```
6. Download the sample ZIPs into `C:\samples`. **Don't unzip them yet.**
7. On the host, run `.\Set-LabNetwork.ps1 -Mode Isolated`. In the VM, `Test-Isolation.ps1` should
   now show everything blocked.
8. Pause protection, unzip the samples, run `--evaluate-corpus` (FILMING.md step 3), put them on the
   Desktop, then:
   ```powershell
   Checkpoint-VM -Name blackshard-film -SnapshotName ready
   ```

Before every take, run `Restore-VMCheckpoint -VMName blackshard-film -Name ready -Confirm:$false`.

## Getting logs out (for debugging with Claude)

Inside the VM, copy `C:\ProgramData\blackshard\State\logs\service.log`, `report.json` and so on to `O:\`.
Then **shut the VM down**, and on the host run:

```powershell
.\Export-LabOutbox.ps1
```

The files land in `exports\<timestamp>\`. Export before you revert, because reverting also rolls back
the outbox.

## New blackshard build

```powershell
.\Update-LabPayload.ps1 -DistPath ..\dist
```

Revert to `base`, copy `dist\` from the BSLAB drive to `C:\blackshard-dist`, then run
`enable-test-signing.ps1`, `install.ps1 -AllowUnsigned` and **restart** (the driver can't be
unloaded). Then retake `base` and `ready`.

## Files

| Script | Runs on | Purpose |
|---|---|---|
| `Setup-Lab.ps1` | host | everything, idempotent |
| `Start-LabSetup.ps1` | host | waits for the ISO, runs Setup-Lab, resumes itself after the restart |
| `Enable-HyperV.ps1` | host | Hyper-V feature |
| `New-BlackshardLab.ps1` | host | switches, NAT, firewall, ACLs, VM, unattend |
| `Set-LabNetwork.ps1` | host | `Isolated` / `Online` / `Off` (no argument shows the current mode) |
| `Update-LabPayload.ps1` | host | repack a new `dist\` into the payload ISO |
| `Export-LabOutbox.ps1` | host | read-only copy of text reports out of the VM |
| `LabCommon.psm1` | host | shared settings: VM size, subnet, names |
| `guest\Setup-Guest.ps1` | VM | first-logon configuration |
| `guest\Test-Isolation.ps1` | VM | reachability check |
| `guest\Get-BlackshardRelease.ps1` | VM | download + verify + test-sign the testing build |
| `guest\Disable-Defender.ps1` | VM | Defender off, no sample upload |

## Removing the lab

```powershell
Stop-VM blackshard-film -TurnOff; Remove-VM blackshard-film -Force
Remove-Item C:\HyperV\blackshard-film -Recurse -Force
Remove-VMSwitch blackshard-isolated, blackshard-online -Force
Remove-NetNat blackshard-online-nat -Confirm:$false
Remove-NetFirewallRule -Name blackshard-lab-*
```
