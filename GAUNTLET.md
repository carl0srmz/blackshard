# The blackshard gauntlet: 100 Windows malware families, easiest to hardest

The ranking is how hard each family is for **blackshard** to detect, kill and fully repair, given the
code on `main` today. It is not a ranking of how dangerous each one is. Each block of 25 is
a step up.

"Needs" is what blackshard must do to win that match-up. ✓ marks what it does now; **bold**
marks what it still cannot do. None of it has run against the real samples yet: that is what the
series is for.

**Safety:** run every sample in a disposable, network-isolated VM only, never on a machine you
care about. Download samples **inside that VM**, not on your own computer.

## Where the samples come from

Every entry has a research source you can get it from yourself. blackshard does not host or
redistribute samples.

| Code | Source | Access |
|------|--------|--------|
| MB | [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch) | free account and Auth-Key; search by signature or tag; zip password `infected` |
| VXU | [vx-underground](https://vx-underground.org) | free; family and APT archives; zip password `infected` |
| ZOO | [theZoo](https://github.com/ytisf/theZoo) | public GitHub repository of live samples |
| EMD | Endermanch's MalwareDatabase (GitHub) | public repository of jokeware and classic samples |
| GitHub | open-source tools | build them yourself |

**✱ marks entries I could not confirm are in a public repository.** Search MalwareBazaar for
them first; if one isn't there, swap it for another member of the same family.

The availability above comes from what these repositories are known to hold, not from checking
each one today. MalwareBazaar's search needs an account, so confirm each sample before you plan
an episode around it.

**Three need more than the file:** BlackLotus (#98) only does anything on a UEFI VM with Secure
Boot on and an unpatched boot manager; the old worms (#19–25) can't exploit a patched Windows 10,
so they only test detection, not spread; and the C2 implants (#87–89, #100) need a listener you
run yourself, inside the isolated network.

---

## Tier 1 (1–25): show-offs and old classics

User-mode, one binary, noisy, and in every signature database. The new turbo path (freeze,
suspend-then-kill, boot-record and registry repair) was built for these.

| # | Name | What it is | Needs | Where |
|---|------|-----------|-------|-------|
| 1 | MEMZ | GDI trojan: overwrites the MBR, watchdog copies | ✓ signature; ✓ suspend-all kill; ✓ MBR restore | EMD, ZOO |
| 2 | BonziBuddy | Adware/spyware assistant | ✓ PUA signatures (opt-in setting) | EMD |
| 3 | Bonzify | Script that force-installs BonziBuddy | ✓ AMSI; ✓ PUA signatures | EMD/GitHub ✱ |
| 4 | Monoxide | GDI screen trojan | ✓ signature; ✓ desktop repaint | ✱ GDI-scene uploads |
| 5 | NoEscape | GDI trojan, destructive payload | ✓ signature; ✓ boot-record and registry repair | EMD |
| 6 | Mrs. Major | Creepy screen trojan, lock-out policies | ✓ policy-tree repair | EMD |
| 7 | Hydra | Respawns more windows each time one is closed | ✓ suspend-all kill | EMD |
| 8 | Rensenware | Joke ransomware (unlock by game score) | ✓ rollback; ✓ decoy documents | EMD, MB |
| 9 | Annabelle | Showy ransomware: MBR, Task Manager lock, IFEO | ✓ MBR, IFEO and policy repair | MB |
| 10 | Jigsaw | Ransomware that deletes files every hour | ✓ decoys; ✓ rollback of deletions | MB, ZOO |
| 11 | ILOVEYOU | VBS mass-mailer, overwrites media files | ✓ AMSI for WSH; ✓ media files in rollback | ZOO, VXU |
| 12 | Anna Kournikova | VBS mass-mailer | ✓ AMSI | VXU ✱ |
| 13 | Melissa | Word macro worm | ✓ VBA analysis; ✓ Office-child rule | VXU |
| 14 | Krotten | Registry vandal, lock-outs | ✓ policy and association tree repair | VXU ✱ |
| 15 | Reveton | Police-themed screen locker | ✓ kill; ✓ Winlogon repair; ✓ global hotkey | MB, VXU |
| 16 | WinLocker family | Ransom screen lockers | ✓ kill; ✓ Winlogon shell repair; ✓ global hotkey | MB, VXU |
| 17 | WinFixer | Rogue "antivirus" scareware | ✓ PUA; ✓ autostart cleanup | VXU ✱ |
| 18 | Brontok | Mass-mailer, disables regedit and folder options | ✓ policy repair | MB, VXU |
| 19 | Blaster | RPC worm | ✓ signature (the exploit is patched on modern Windows) | VXU, ZOO |
| 20 | Sasser | LSASS worm | ✓ signature | VXU, ZOO |
| 21 | MyDoom | Mass-mailer and DDoS bot | ✓ signature; ✓ Run cleanup | VXU, ZOO |
| 22 | Netsky | Mass-mailer | ✓ signature | VXU, ZOO |
| 23 | Bagle | Mass-mailer and backdoor | ✓ signature; ✓ services and hosts-file repair | VXU, ZOO |
| 24 | Sobig | Mass-mailer | ✓ signature | VXU, ZOO |
| 25 | Koobface | Social-network worm | ✓ signature; ✓ Run cleanup | VXU |

## Tier 2 (26–50): outbreaks, classic ransomware, infectors, adware

Stable binaries with good signatures. The difficulty here is **repair**: files encrypted
beyond the rollback vault's limits, files infected rather than dropped, and system changes
outside the watched list.

| # | Name | What it is | Needs | Where |
|---|------|-----------|-------|-------|
| 26 | Petya (2016) | MBR bootlocker, encrypts the MFT on reboot | ✓ kill before reboot; ✓ MBR restore; ✓ boot-record scan | MB, ZOO |
| 27 | NotPetya | Wiper posing as ransomware, spreads with EternalBlue and credentials | ✓ early kill; ✓ MBR; ✓ shadow-copy rule; ✓ remote-execution and disguised-DLL rules | MB, ZOO |
| 28 | WannaCry | SMB worm ransomware | ✓ kill; ✓ decoys; ✓ larger rollback vault | MB, ZOO |
| 29 | Bad Rabbit | Fake Flash, disk encryption via a signed driver | ✓ shadow-copy rule; ✓ loaded-driver scan; **driver-based disk encryption** | MB, ZOO |
| 30 | CryptoLocker | Classic ransomware | ✓ heuristic; ✓ decoys; ✓ rollback | MB, ZOO |
| 31 | CryptoWall | Ransomware, injects into explorer | ✓ memory hunt stops injected threads in Explorer | MB, ZOO |
| 32 | TeslaCrypt | Ransomware | ✓ heuristic; ✓ decoys; ✓ rollback | MB, ZOO |
| 33 | Locky | Macro-delivered ransomware | ✓ VBA; ✓ Office-child rule; ✓ decoys; ✓ rollback | MB, ZOO |
| 34 | Cerber | Ransomware with a spoken note | ✓ heuristic; ✓ decoys; ✓ rollback | MB, ZOO |
| 35 | GandCrab | Ransomware-as-a-service | ✓ heuristic; ✓ decoys; ✓ rollback | MB, ZOO |
| 36 | Satana | Files plus MBR | ✓ heuristic; ✓ MBR restore | MB, ZOO |
| 37 | STOP/Djvu | The most common consumer ransomware | ✓ heuristic; ✓ decoys; ✓ hosts-file repair | MB, ZOO |
| 38 | Phobos | Ransomware, deletes shadow copies | ✓ shadow-copy rule; ✓ decoys | MB, ZOO |
| 39 | Dharma/CrySiS | RDP-delivered ransomware | ✓ heuristic; ✓ decoys; ✓ rollback | MB, ZOO |
| 40 | Conficker | Runs as a service DLL inside svchost | ✓ ServiceDll cleanup; ✓ injected-thread kill in svchost | ZOO, VXU |
| 41 | Virut | File infector | ✓ SFC for Windows files; **disinfection of other programs** | MB, VXU |
| 42 | Sality | File infector, kills AVs | ✓ SFC; ✓ self-protection; **disinfection** | MB, VXU |
| 43 | Ramnit | File infector and banking trojan | ✓ SFC; **disinfection** | MB, VXU |
| 44 | Neshta | File infector | ✓ SFC; **disinfection** | MB, VXU |
| 45 | Fireball | Browser hijacker | ✓ browser policy repair; **browser settings outside policy** | MB ✱ |
| 46 | InstallCore | Bundler | ✓ PUA | MB |
| 47 | Superfish | Adware with a root certificate | ✓ root certificate repair | ✱ |
| 48 | Wajam | Evasive adware | ✓ PUA; ✓ browser policy repair; **browser settings outside policy** | MB ✱ |
| 49 | Adrozek | Browser modifier | ✓ browser policy repair; **browser files it patches** | MB ✱ |
| 50 | ChromeLoader | Malicious extension plus PowerShell scheduled task | ✓ task cleanup by rule; ✓ forced-extension policy repair; ✓ `--load-extension` rule | MB |

## Tier 3 (51–75): modern crimeware

Packed, polymorphic, often never written to disk in clear. They inject into trusted processes,
live off Windows' own binaries, and phone home. Signatures alone lose here.

| # | Name | What it is | Needs | Where |
|---|------|-----------|-------|-------|
| 51 | RedLine | Infostealer | ✓ memory scanning; ✓ browser credential-store guard | MB |
| 52 | Raccoon | Infostealer | ✓ memory scanning; ✓ browser credential-store guard | MB |
| 53 | Vidar | Infostealer | ✓ memory scanning; ✓ browser credential-store guard | MB |
| 54 | Lumma | Infostealer, often delivered by a pasted command ("ClickFix") | ✓ ClickFix command-line rules; ✓ AMSI | MB |
| 55 | Agent Tesla | .NET stealer and keylogger | ✓ memory scanning; ✓ in-memory loader rule | MB |
| 56 | FormBook/XLoader | Stealer, process hollowing | ✓ memory scanning; ✓ hollowing detection | MB |
| 57 | Remcos | RAT | ✓ signature; ✓ injected-thread kill | MB |
| 58 | njRAT | .NET RAT | ✓ signature; ✓ firewall-rule repair | MB |
| 59 | AsyncRAT | .NET RAT | ✓ signature; ✓ in-memory loader rule; ✓ memory scanning | MB |
| 60 | Quasar | .NET RAT | ✓ signature | MB |
| 61 | DarkComet | RAT | ✓ signature | MB |
| 62 | NanoCore | .NET RAT | ✓ signature | MB |
| 63 | XWorm | RAT and worm | ✓ signature; ✓ hidden-USB-program block | MB |
| 64 | DarkGate | Loader delivered as an AutoIt script | ✓ AutoIt-loader rule | MB |
| 65 | Zeus/Zbot | Banking trojan, injects into explorer | ✓ injected-thread kill | MB |
| 66 | Emotet | Loader with service persistence | ✓ service cleanup; ✓ memory scanning; **polymorphism** | MB |
| 67 | TrickBot | Modular, injects | ✓ injected-thread kill; ✓ task cleanup | MB |
| 68 | QakBot | Loader, injects into wermgr and explorer | ✓ injected-thread kill | MB |
| 69 | IcedID | Loader, DLL side-loading | ✓ side-loading rule | MB |
| 70 | Dridex | Banking, DLL hijacking | ✓ side-loading rule | MB |
| 71 | Ursnif/Gozi | Banking, registry-stored payloads | ✓ autostart sweep; ✓ registry payload removal | MB |
| 72 | SmokeLoader | Loader, injects into explorer | ✓ injected-thread kill | MB |
| 73 | GuLoader | Shellcode loader, anti-VM | ✓ memory scanning; ✓ works in VMs | MB |
| 74 | SocGholish | Fake browser update in JavaScript | ✓ downloaded-script rule; ✓ download-zone rule | MB |
| 75 | Raspberry Robin | USB worm using msiexec and other built-in tools | ✓ msiexec and LOLBin rules | MB |

## Tier 4 (76–100): human-operated, fileless, kernel and firmware

These kill or blind security products, run below the OS, or never touch disk. No antivirus
"always" wins these. The bar is to survive, detect and contain them.

| # | Name | What it is | Needs | Where |
|---|------|-----------|-------|-------|
| 76 | LockBit 3.0 | Ransomware, kills services, fast encryption | ✓ self-protection; ✓ shadow-copy rule; ✓ decoys | MB |
| 77 | BlackCat/ALPHV | Rust ransomware | ✓ self-protection; ✓ shadow-copy rule; ✓ decoys | MB |
| 78 | Conti | Ransomware | ✓ self-protection; ✓ shadow-copy rule; ✓ decoys | MB |
| 79 | Ryuk | Ransomware, targets backups | ✓ shadow-copy and backup rules; ✓ decoys | MB |
| 80 | REvil | Ransomware, reboots into Safe Mode to encrypt | ✓ Safe Mode protection; ✓ Safe Mode reboot rule | MB |
| 81 | Black Basta | Ransomware, Safe Mode | ✓ Safe Mode protection; ✓ Safe Mode reboot rule | MB |
| 82 | Akira | Ransomware | ✓ shadow-copy rule; ✓ decoys | MB |
| 83 | Play | Ransomware, intermittent encryption | ✓ decoys catch intermittent encryption | MB |
| 84 | Royal/BlackSuit | Partial encryption | ✓ decoys catch partial encryption | MB |
| 85 | Cl0p | Ransomware and data theft | ✓ decoys; **data-theft visibility** | MB |
| 86 | Rhysida | Ransomware | ✓ shadow-copy rule; ✓ decoys | MB |
| 87 | Cobalt Strike Beacon | Post-exploitation, reflective loading | ✓ memory scanning; ✓ default pipe names; **network visibility** | MB |
| 88 | Sliver | Open-source C2 implant | ✓ memory scanning; **network visibility** | GitHub (build the implant) |
| 89 | Brute Ratel C4 | C2 built to evade EDRs | ✓ memory scanning; **unhooking and direct-syscall evasion** | MB |
| 90 | Kovter | Fileless: payload stored in the registry | ✓ autostart sweep; ✓ registry payload removal | MB, VXU |
| 91 | Poweliks | Fileless: registry plus rundll32 and JavaScript | ✓ rundll32 and mshta rules; ✓ autostart sweep; ✓ registry payload removal | VXU |
| 92 | Purple Fox | Rootkit and worm, MSI-delivered | ✓ msiexec rule; ✓ hidden-process and loaded-driver scan | MB |
| 93 | ZeroAccess | Rootkit, click-fraud | ✓ hidden-process and loaded-driver scan; **removal needs an offline scan** | ZOO, VXU |
| 94 | TDL4/TDSS | MBR bootkit | ✓ MBR restore; ✓ boot-record scan | ZOO, VXU |
| 95 | Necurs | Rootkit driver | ✓ vulnerable driver blocklist; ✓ loaded-driver scan, disable and quarantine | MB, VXU |
| 96 | FiveSys | Microsoft-signed rootkit driver | ✓ loaded-driver scan by signature; **trust beyond Microsoft's signature** | ✱ VirusTotal only |
| 97 | AuKill / Terminator | Bring-your-own-vulnerable-driver AV killers | ✓ self-protection; ✓ vulnerable driver blocklist | MB |
| 98 | BlackLotus | UEFI bootkit, bypasses Secure Boot | ✓ EFI partition scan; **repair needs bcdboot and Secure Boot updates** | MB; GitHub proof of concept |
| 99 | Mimikatz | Credential dumper, the standard post-exploitation tool | ✓ LSA protection (Windows 11 22H2+); ✓ credential-dumping rules; ✓ signature | GitHub |
| 100 | Meterpreter | Memory-only implant, reflective DLL injection | ✓ memory scanning; **network visibility** | GitHub (Metasploit) |
