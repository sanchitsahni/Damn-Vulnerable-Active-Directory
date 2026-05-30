# dc01.corp.local — 10.10.0.10

Forest root DC for `corp.local`. **Every** classic AD attack lands here first: it holds krbtgt, runs Spooler + EFSRPC + WebClient + DFSNM (all coercion primitives), exposes null-session pipes, allows zone transfer, ADIDNS is writable, LDAP signing is off, and the password policy is the lab default.

## Listening ports

| Port | Proto | Service | Notes |
|---|---|---|---|
| 53 | TCP/UDP | DNS | AXFR open, dynamic updates accepted from auth users |
| 88 | TCP/UDP | Kerberos KDC | RC4 enabled (`msDS-SupportedEncryptionTypes=0x7`) |
| 123 | UDP | W32Time | NTP, also used by ZeroLogon path indirectly |
| 135 | TCP | RPC endpoint mapper | enumerate all dyn-port RPC interfaces |
| 137-139 | TCP/UDP | NetBIOS | NBT-NS active |
| 389 | TCP | LDAP | signing not required → unauthenticated bind tolerated |
| 445 | TCP | SMB | signing required (DC default) — *server-side*; client signing off |
| 464 | TCP/UDP | kpasswd | password change |
| 593 | TCP | RPC over HTTP | rarely used but reachable |
| 636 | TCP | LDAPS | cert issued by ca01 |
| 3268-3269 | TCP | Global Catalog (LDAP/LDAPS) | forest-wide search |
| 3389 | TCP | RDP | NLA default; firewall rule on |
| 5985 | TCP | WinRM HTTP | `AllowUnencrypted=true`, Basic + CredSSP |
| 9389 | TCP | ADWS | SOAP wrapper around DC data |

## Reachable RPC pipes (after null session, then authed)

| Pipe | Null? | Authed? | What you get |
|---|---|---|---|
| `\PIPE\lsarpc` | Y | Y | SIDs, domain policy, trust list |
| `\PIPE\samr` | Y | Y | users, groups, password policy |
| `\PIPE\netlogon` | Y | Y | NRPC — **ZeroLogon target** |
| `\PIPE\srvsvc` | Y | Y | shares, sessions (NetSessionEnum) |
| `\PIPE\browser` | Y | Y | legacy browse list |
| `\PIPE\wkssvc` | N | Y | logged-on users, transports |
| `\PIPE\svcctl` | N | Y (admin) | service control |
| `\PIPE\winreg` | N | Y | remote registry |
| `\PIPE\atsvc` | N | Y | scheduled tasks |
| `\PIPE\eventlog` | N | Y | event log read |
| `\PIPE\spoolss` | N | Y | **PrinterBug / PrintNightmare** |
| `\PIPE\drsuapi` | N | Y (DCSync rights) | replication / DCSync |
| `\PIPE\efsrpc` | N | Y | **PetitPotam** |
| `\PIPE\dfsnm` | N | Y | **DFSCoerce** |
| `\PIPE\dnsserver` | N | Y (DnsAdmins) | server-level plugin DLL load → RCE |
| `\PIPE\fssagentrpc` | N | Y | **ShadowCoerce** (VSS) |

## Shares

| Share | Path | ACL highlights | Bait |
|---|---|---|---|
| `SYSVOL` | `C:\Windows\SYSVOL\sysvol` | Auth Users R, scripts folder M | `Groups.xml` (cpassword), `login.bat`, `map_backup.bat` |
| `NETLOGON` | `C:\Windows\SYSVOL\sysvol\corp.local\SCRIPTS` | Auth Users R | logon scripts with cleartext |
| (default admin) `C$`, `ADMIN$`, `IPC$` | — | admin-only | use after PtH |

## Users / groups / SPNs to grep for

```
svc_vision        SPN: HTTP/web.corp.local                RC4 only, ConstrainedDelegation→ws01
svc_jarvis        SPN: MSSQLSvc/sql01.corp.local:1433
svc_thanos                                          DONT_REQ_PREAUTH    (AS-REP)
no_preauth_svc                                          DONT_REQ_PREAUTH    (AS-REP)
heimdall                                             Backup Operators + reversible
nick.fury                                                Account Operators, Print Operators, Schema Admins
doctor.strange                                               DCSync (Replicating Changes + ChangesAll)
developer1                                              DnsAdmins, Server Operators, many privs
gmsa01                                                  Attacker can retrieve managed pwd
former_admin                                            Disabled DA, attacker has GenericAll
svc_legacy                                              TRUSTED_FOR_DELEGATION (Unconstrained)
PRE2K01$                                                PASSWD_NOTREQD; pwd = pre2k01
```

## ADIDNS

Authenticated Users have `CreateChild` on the AD-integrated zone → register `wpad.corp.local`, `new-fileserver.corp.local`, etc. → MITM.

## Hardening that is OFF

- LLMNR re-enabled
- IPv6 enabled (mitm6 viable)
- `RestrictAnonymous=0`, `RestrictNullSessAccess=0`, `EveryoneIncludesAnonymous=1`
- `LmCompatibilityLevel=2` (NTLMv1 accepted)
- WDigest UseLogonCredential=1 (cleartext in LSASS)
- `LSAProtection (RunAsPPL)=0`
- LDAP signing not required, channel binding off
- Defender disabled
- `FullSecureChannelProtection=0` → **ZeroLogon viable**
- Print Spooler auto-started

## Minimum enum sweep (paste these)

```bash
DC=10.10.0.10
# Anonymous
enum4linux-ng -A $DC
nxc smb $DC -u '' -p ''
impacket-rpcdump $DC
impacket-lookupsid 'corp.local/'@$DC 10000
ldapsearch -x -H ldap://$DC -s base -b "" "(objectclass=*)"
dig @$DC corp.local AXFR
kerbrute userenum -d corp.local --dc $DC users.txt
impacket-GetNPUsers corp.local/ -dc-ip $DC -no-pass -usersfile users.txt -format hashcat
# Coercion gates
nxc smb $DC -M petitpotam,dfscoerce,printerbug,spooler,webdav,ms17-010
# ZeroLogon
python3 zerologon_tester.py DC01 $DC
# After first credential
bloodhound-python -u peter.parker -p 'DVADlab2024!' -d corp.local -ns $DC -c all
nxc smb,ldap $DC -u peter.parker -p 'DVADlab2024!' \
    --users --groups --pass-pol --kerberoasting kerb.txt --asreproast asrep.txt \
    --trusted-for-delegation --password-not-required --admin-count --gmsa
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip $DC -vulnerable -stdout
```

## What this host enables (forward links)

REC-001..015, CRED-001/002/013/014/018/020/021/022/023, LAT-001..035, PE-018/057, PER-018, DF-001..040 (every domain compromise eventually touches dc01).
