# Enterprise AD CTF Lab - "Game of AD v3.0"
## Comprehensive Active Directory, Hybrid Cloud & Windows Privilege Escalation Attack Research

> **Project:** Internal Enterprise CTF Challenge (QEMU/Proxmox Deployable)
> **Classification:** Internal Use Only
> **Scope:** Multi-Forest AD + Hybrid Entra ID, Exchange, SCCM, WSUS, Linux pivots, ADCS ESC1-16, every modern attack vector, no attacker VM needed
> **Aligns with:** `ad-architechture.html` Attack Architecture Map v1.1

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Enterprise Architecture Overview](#2-enterprise-architecture-overview)
3. [Complete Attack Vectors Matrix](#3-complete-attack-vectors-matrix)
4. [VM Manifest & Sizing](#4-vm-manifest--sizing)
5. [Network Design](#5-network-design)
6. [Deployment Architecture](#6-deployment-architecture)
7. [OS Media Strategy](#7-os-media-strategy)
8. [Activation Strategy](#8-activation-strategy)
9. [Risk Mitigation](#9-risk-mitigation)
10. [Research Sources & References](#10-research-sources--references)
11. [Hybrid Cloud — Azure AD / Entra ID Attack Paths](#11-hybrid-cloud--azure-ad--entra-id-attack-paths)
12. [Exchange Server Attack Surface](#12-exchange-server-attack-surface)
13. [SCCM / MECM Attack Matrix](#13-sccm--mecm-attack-matrix)
14. [WSUS Attack Surface](#14-wsus-attack-surface)
15. [MSSQL Deep Dive](#15-mssql-deep-dive)
16. [Linux-in-AD Attack Surface](#16-linux-in-ad-attack-surface)
17. [DPAPI Deep Dive](#17-dpapi-deep-dive)
18. [Coercion Techniques Catalog](#18-coercion-techniques-catalog)
19. [Attack Flow Chains (End-to-End)](#19-attack-flow-chains-end-to-end)
20. [Defense Suppression & Evasion (Protected Users / AMSI / CLM / WDAC)](#20-defense-suppression--evasion-protected-users--amsi--clm--wdac)
21. [ASP.NET ViewState / Web RCE Component](#21-aspnet-viewstate--web-rce-component)
22. [Common Misconfigurations Audit Checklist](#22-common-misconfigurations-audit-checklist)
23. [Architecture-to-PLAN Cross-Reference](#23-architecture-to-plan-cross-reference)

---

## 1. Executive Summary

This lab implements a **complete, enterprise-grade Active Directory CTF environment** designed to train internal red/blue teams on **every known AD and Windows privilege escalation technique**. The lab is:

- **Multi-Forest**: `corp.local` + `finance.local` + external `contractor.corp`
- **Multi-Domain**: Parent-child trust within `corp.local`
- **Self-Deploying**: Single `./deploy.sh` command on any Debian/Ubuntu/Fedora host
- **Lightweight**: Uses Windows Server Core + trimmed Nano options
- **External attacker model**: the attacker is a Kali/BlackArch box on the host bridge (`10.10.0.1`) — *not* a lab VM. `ws01.corp.local` is a **victim** workstation (phishing landing, lateral target). All attacks start from outside the lab and earn their way in.
- **QEMU Native**: Direct QEMU/KVM on Proxmox compatibility
- **Ansible-Automated**: Full post-deployment hardening and vulnerability injection

---

## 2. Enterprise Architecture Overview

### 2.1 Forest Topology

```
                              +---------------------------+
                              |   ENTERPRISE ROOT         |
                              |   Forest: ROOT.CORP       |
                              |   DC01.root.corp          |
                              |   (Windows Server Core)   |
                              +-------------+-------------+
                                            |
              +-----------------------------+-----------------------------+
              |                                                           |
+-------------v-------------+                               +-------------v-------------+
|  Forest: CORP.LOCAL       |                               |  Forest: FINANCE.LOCAL    |
|  am.corp.local            |                               |  dc01.finance.local       |
|  eu.corp.local (child)    |                               |  (Windows Server Core)    |
|  dc01.corp.local          |                               +-------------+-------------+
|  (Windows Server Core)    |                                             |
+-------------+-------------+                               External Trust |
              |                                                           v
    +---------+---------+                                       contractor.corp
    |                   |                                       (stub forest)
+---v--------+   +------v------+
| dc01.eu.   |   | ws01.corp   |   +---------------------------+
| corp.local |   | .local      |   |  ADCS Server              |
| (child DC) |   | (Victim     |   |  ca01.corp.local          |
|            |   |  Workstation)|   |  (ESC1-16 Templates)      |
+------------+   +-------------+   +---------------------------+

Trusts:
  - ROOT.CORP <~> CORP.LOCAL (Tree-Root)
  - ROOT.CORP <~> FINANCE.LOCAL (External)
  - CORP.LOCAL parent <~> eu.corp.local child
  - FINANCE.LOCAL <~> contractor.corp (One-way incoming)
```

### 2.2 Domain Layout

**Domain A: `corp.local` (Primary Playground)**
| Object | Type | Purpose |
|--------|------|---------|
| dc01.corp.local | DC1 | Main target, all principal vulnerabilities |
| dc01.eu.corp.local | Child DC | ExtraSID / SID-History attacks |
| ca01.corp.local | Server | ADCS with all ESC attack vectors |
| ws01.corp.local | Workstation | Victim workstation — phishing landing (IA-019..022), lateral target, credential harvesting source |
| sql01.corp.local | Server | MSSQL constrained delegation target |
| file01.corp.local | Server | File server, ACL abuse, unconstrained delegation |

**Domain B: `finance.local` (Trust Target)**
| Object | Type | Purpose |
|--------|------|---------|
| dc01.finance.local | DC1 | SID filtering bypass, cross-forest attacks |
| ws01.finance.local | Workstation | Cross-forest lateral movement target |

**Domain C: `root.corp` (Enterprise Root)**
| Object | Type | Purpose |
|--------|------|---------|
| dc01.root.corp | DC1 | Enterprise Admin target, schema admin attacks |

---

## 3. Complete Attack Vectors Matrix

### Category Legend
- **IA** = Initial Access (external attacker → first foothold)
- **REC** = Reconnaissance
- **ENUM** = Enumeration surface (services / pipes / protocols enabled lab-wide)
- **CRED** = Credential Access
- **LAT** = Lateral Movement
- **PE** = Privilege Escalation
- **PER** = Persistence
- **DF** = Domain/Forest compromise
- **ADCS** = Active Directory Certificate Services
- **KRB** = Kerberos-specific
- **ACL** = Access Control List Abuse

### Phase 0: Initial Access (Flags IA-001 to IA-050)

> The attacker starts on a **Kali / BlackArch** host on the bridge subnet (`10.10.0.0/21` / `10.20.0.0/24` / `10.30.0.0/24`) with **zero credentials and zero AD foothold**. Phase 0 is everything that gets you to "I have a shell / hash / cleartext on a domain-joined box or a usable AD identity." Full per-vector writeups in [`docs/02a-initial-access.md`](docs/02a-initial-access.md).

| ID | Technique | CVE/Ref | Pre-condition | Vuln Config |
|----|-----------|---------|---------------|-------------|
| IA-001 | Network sweep (nmap/masscan) | N/A | L3 reach to lab bridge | Default — hosts respond to scans |
| IA-002 | SMB null/guest session enumeration | N/A | SMB 445 reachable | `RestrictAnonymous=0`, guest enabled on file01 |
| IA-003 | Anonymous LDAP bind | N/A | LDAP 389 reachable | `dsHeuristics` permits anon read |
| IA-004 | DNS AXFR zone transfer | N/A | DNS 53 reachable | AD-integrated zone allows transfer to Any |
| IA-005 | Kerberos username enumeration (kerbrute userenum) | N/A | KDC 88 reachable | KDC returns PRINCIPAL_UNKNOWN vs CLIENT_REVOKED |
| IA-006 | Unauthenticated AS-REP roast (no creds) | N/A | Valid username + DoNotRequirePreAuth | `svc_nopreauth` set DONT_REQ_PREAUTH |
| IA-007 | Password spray (kerbrute / nxc) | N/A | Username list | Default `Password123!` on ~15% of accounts |
| IA-008 | LLMNR/NBT-NS poisoning (Responder) | N/A | Same L2 segment | LLMNR + NBT-NS enabled domain-wide |
| IA-009 | mitm6 IPv6 DHCP takeover | N/A | Attacker on victim L2 | IPv6 enabled, no DHCPv6 guard |
| IA-010 | WPAD poisoning via Responder | N/A | LLMNR on, no GPO WPAD | Default WPAD lookup behavior |
| IA-011 | Unauthenticated MSSQL (PUBLIC + xp_cmdshell) | N/A | MSSQL 1433 reachable | `sa` weak password / public xp_cmdshell |
| IA-012 | PetitPotam unauth coercion to attacker | CVE-2021-36942 | EFSRPC reachable | EFSRPC unauth allowed on DC/file01 |
| IA-013 | Coerce + NTLM relay to ADCS (unauth chain) | N/A | EFSRPC + ADCS HTTP web enrollment | Web enrollment NTLM + no EPA |
| IA-014 | ZeroLogon (no creds) | CVE-2020-1472 | Netlogon RPC reachable | Unpatched DC, `FullSecureChannelProtection=0` |
| IA-015 | PrintNightmare RCE (unauth Print Spooler) | CVE-2021-34527 | Spooler 445 reachable | Spooler enabled, July 2021 patch missing |
| IA-016 | EternalBlue / SMBGhost | MS17-010 / CVE-2020-0796 | SMB 445 reachable, unpatched | Old patch level on a workstation |
| IA-017 | ProxyShell / ProxyNotShell (Exchange) | CVE-2021-34473 + chain | Exchange OWA reachable | Unpatched Exchange (lab variant) |
| IA-018 | Log4Shell on internal web app | CVE-2021-44228 | Vulnerable app reachable | JNDI lookup enabled |
| IA-019 | Phishing — macro doc → Office spawn | N/A | User opens attachment | Macros enabled, no ASR |
| IA-020 | Phishing — LNK with PowerShell | N/A | User double-clicks | Mark-of-the-Web bypass |
| IA-021 | Phishing — ISO/IMG container | N/A | User mounts container | MOTW bypassed via container |
| IA-022 | Phishing — HTA / mshta | N/A | User runs HTA | mshta not blocked |
| IA-023 | Phishing — OAuth consent / illicit grant | N/A | Hybrid Entra | App registration with broad scopes |
| IA-024 | Phishing — library-ms file (CVE-2025-24071) | CVE-2025-24071 | User opens .library-ms | Auto-NTLM leak via Explorer preview |
| IA-025 | VPN / edge appliance CVE (Citrix, Fortinet, etc.) | various | Edge device exposed | Unpatched gateway |
| IA-026 | Web app RCE → reverse shell | N/A | Vulnerable internal web app | Path traversal / upload / RCE |
| IA-027 | RDP brute / NLA bypass | N/A | 3389 reachable | Weak local admin password |
| IA-028 | USB / HID-drop (Rubber Ducky) | N/A | Physical access | Default Autorun policy bypass via HID |
| IA-029 | SCCM PXE boot media without password | N/A | Attacker on PXE VLAN | PXE password not enforced; NAA in policy |
| IA-030 | VLAN hop (DTP / double-tag) | N/A | Trunk port misconfig | Switch DTP auto |
| IA-031 | Watering-hole on internal wiki / SharePoint | N/A | Write to internal site | SharePoint allows arbitrary HTML |
| IA-032 | Entra ID device-code phishing | N/A | Hybrid join + Entra | Device-code flow enabled, no CA policy |
| IA-033 | Initial C2 stand-up (Sliver / Mythic / Havoc) | N/A | Any of IA-019..028 succeeds | EDR off on `ws01` |
| IA-034 | SNMP public/private community RO+RW | N/A | UDP 161 reachable | `public`/`private` communities on every server |
| IA-035 | Anonymous IIS FTP on file01 | N/A | TCP 21 reachable | `Web-Ftp-Server` installed, anon allowed |
| IA-036 | Telnet brute on file01 | N/A | TCP 23 reachable | `TlntSvr` running |
| IA-037 | Anonymous NFS r/w share on file01 | N/A | TCP/UDP 2049 reachable | `DVAD_NFS` export with `EnableAnonymousAccess=$true` |
| IA-038 | SMB1 / EternalBlue surface on file01 | MS17-010 | TCP 445 reachable | `FS-SMB1` enabled + reg `SMB1=1` (file01 only) |
| IA-039 | IIS WebDAV PROPFIND + relay endpoint on ca01 | N/A | HTTP 80 reachable | `Web-DAV-Publishing` + `Web-Dir-Browsing` on ca01 |
| IA-040 | WinRM-HTTPS (5986) self-signed cert | N/A | TCP 5986 reachable | Self-signed listener on every host |
| IA-041 | DNS AXFR open on every DC | N/A | UDP/TCP 53 reachable | `SecureSecondaries=TransferAnyServer` on all DCs |
| IA-042 | Null-session pipes on every DC | N/A | SMB 445 reachable | `RestrictAnonymous=0` + `NullSessionPipes` lab-wide |
| IA-043 | RDP NLA-off on ws01 (BlueKeep gate) | CVE-2019-0708 | TCP 3389 reachable | `UserAuthentication=0` on ws01 |
| IA-044 | Print Spooler / PrinterBug from any member | CVE-2021-34527 var. | RPC reachable | Spooler on every member + `DVAD-PRN` shared on file01 |
| IA-045 | WebClient HTTP coercion path | N/A | WebClient running anywhere | `WebClient` set auto-start on every host |
| IA-046 | ADWS (9389) enumeration on every DC | N/A | TCP 9389 reachable | `ADWS` service forced auto-start |
| IA-047 | WSD / SSDP passive sniff | N/A | Same L2 segment | `FDResPub`/`SSDPSRV`/`fdPHost` running everywhere |
| IA-048 | SQL Browser broadcast discovery (UDP 1434) | N/A | UDP 1434 reachable | `SQLBrowser` auto-start on sql01 |
| IA-049 | IIS WebDAV PUT → ASPX webshell on ca01 | N/A | WebDAV write permitted | Default IIS WebDAV write ACLs |
| IA-050 | SNMP `private` (RW) → service-path hijack | N/A | UDP 161 reachable, `private` configured | Community-string RW = registry write |



| ID | Technique | CVE/Ref | Path | Vuln Config |
|----|-----------|---------|------|-------------|
| REC-001 | Domain Enumeration (LDAP/ADWS) | N/A | Domain user read access | None needed - standard AD queries |
| REC-002 | SPN Enumeration (Get-ADUser -Filter {SPN} -Properties *) | N/A | All users have list access | None - AD default |
| REC-003 | BloodHound SharpHound Ingestor | N/A | Any authenticated user | None - default read permissions |
| REC-004 | Trust Enumeration (nltest /domain_trusts) | N/A | Domain user | Trusts configured with TGT delegation |
| REC-005 | GPO Enumeration (rsop.msc / gpresult) | N/A | Authenticated Users read | GPOs applied broadly |
| REC-006 | ACL Enumeration (Get-Acl AD objects) | N/A | DCSync requires Replicate Directory Changes | Overly permissive DACL on objects |
| REC-007 | DNS Zone Transfer (AXFR) | N/A | DNS Zone Transfer enabled | Unrestricted zone transfers |
| REC-008 | SMB Share Enumeration (smbclient -L) | N/A | NULL session / guest | Guest account enabled, shares allow Everyone |
| REC-009 | MSSQL Instance Enumeration (PowerUpSQL) | N/A | Public SQL Browser | SQL Browser broadcasting instances |
| REC-010 | LLMNR/NBT-NS Poisoning responder | Absence of DNS suffix | Broadcast protocols enabled | No DNS suffix search list configured |
| REC-011 | Password Policy Enumeration | N/A | Anonymous complex password policy | DefaultDomainPolicy readable |
| REC-012 | ADCS Template Enumeration (certutil -template) | N/A | Domain Users read | Vulnerable templates published |
| REC-013 | Kerberos Pre-auth Enumeration (AS-REP Roasting) | N/A | Users without pre-auth | DoNotRequirePreAuth set on accounts |
| REC-014 | Machine Account Enumeration (hashes) | N/A | Any authenticated user | None - AD default |
| REC-015 | Sensitive Data in SYSVOL/NETLOGON scripts | N/A | Authenticated Users read | Scripts contain passwords |

### Phase 1.5: Enumeration Surface (Flags ENUM-001 to ENUM-080)

> Once you have *any* foothold (anonymous bind, low-priv user, machine account, ticket), DVAD is configured to support the full breadth of Windows / AD enumeration techniques — every named pipe, every protocol, every legacy service. ENUM-001..080 are **not flags** in the CTF sense; they are the catalog of *recon techniques the lab demonstrably exercises*. Full per-technique writeups in [`docs/02b-enumeration.md`](docs/02b-enumeration.md); per-host crib sheets in [`docs/hosts/`](docs/hosts/).
>
> Coverage map (sections, not exhaustive list):
>
> | Range | Section | Examples |
> |---|---|---|
> | ENUM-001..010 | Network surface | nmap/masscan, IPv6 ND, ICMP, ARP, multicast |
> | ENUM-011..020 | SMB + RPC pipes | enum4linux-ng, rpcclient, rpcdump, lookupsid, samrdump, NetSessionEnum |
> | ENUM-021..030 | LDAP / ADWS | ldapsearch UAC filters, BloodHound, SOAPHound, adidnsdump |
> | ENUM-031..040 | Kerberos | kerbrute, getuserspns, AS-REP roast, GetUserSPNs anonymous |
> | ENUM-041..050 | DNS / NetBIOS / LLMNR | AXFR, srv-brute, Responder analyze mode |
> | ENUM-051..060 | Web / IIS / MSSQL / WinRM / RDP | nikto, certipy find, mssqlclient, evil-winrm probe, rdp-ntlm-info |
> | ENUM-061..070 | WMI / DCOM / SNMP / ADCS | wmic, DCOMrade, snmpwalk MIBs, certipy ESC scan |
> | ENUM-071..080 | GPO / SYSVOL / local Windows / hybrid | gpresult, Get-GPPPassword, AzureHound, Sysmon evasion checks |
>
> RPC pipes intentionally reachable across the lab: `lsarpc`, `samr`, `netlogon`, `srvsvc`, `wkssvc`, `svcctl`, `winreg`, `atsvc`, `spoolss`, `eventlog`, `drsuapi`, `efsrpc`, `dfsnm`, `dnsserver`, `fssagentrpc`. See [`docs/02b-enumeration.md`](docs/02b-enumeration.md) §V for the complete pipe → tool → coercion-target table.

### Phase 2: Credential Access (Flags CRED-001 to CRED-065)

| ID | Technique | CVE/Ref | Pre-condition | Vuln Config |
|----|-----------|---------|---------------|-------------|
| CRED-001 | Kerberoasting (TGS-REP, hashcat) | N/A | SPN on account | Service accounts with weak passwords |
| CRED-002 | AS-REP Roasting | N/A | No pre-auth | Account: svc_nospreauth |
| CRED-003 | Password Spray | N/A | Multiple user accounts | Common default password Password123! on 15% of accounts |
| CRED-004 | Credential Hunting (browser, PuTTY, DBeaver) | N/A | Local admin on workstation | Saved passwords in tools |
| CRED-005 | LSASS Memory Dump (mimikatz sekurlsa::logonpasswords) | N/A | Local admin + ANTIVIRUS OFF | Debug privilege granted to Administrators |
| CRED-006 | SAM Database Extraction (reg save HKLM SAM) | N/A | System or backup privilege | SeBackupPrivilege on some accounts |
| CRED-007 | NTDS.dit Extraction (Volume Shadow Copy) | N/A | Domain admin or backup ops | Backup Operators -> DCSync |
| CRED-008 | Shadow Credentials (msDS-KeyCredentialLink) | N/A | GenericWrite on user | msDS-KeyCredentialLink writable by delegated group |
| CRED-009 | Reversible Password Encryption | N/A | Admin on DC | User: backup_user has allowReversiblePasswordEncryption = $true |
| CRED-010 | Token Impersonation (incognito, sekurlsa::tickets) | N/A | Process in target session | Services running as different users |
| CRED-011 | Pass-the-Hash (NTLM relay / Mimikatz pth) | N/A | NTLM hash | LM/NTLMv1 enabled on some accounts |
| CRED-012 | Pass-the-Ticket (Rubeus ptt) | N/A | Valid TGT/TGS | None - standard Kerberos |
| CRED-013 | DCSync (lsadump::dcsync) | N/A | Replicate Directory Changes | Backup Operators have Replicate Directory Changes |
| CRED-014 | DCSync w/ Replication-Get-Changes-All | N/A | Same as above, higher tier | Account: sync_user has GetChangesAll |
| CRED-015 | DCShadow (rogue DC push) | N/A | Write to Domain Controllers OU | Schema Admin delegated loosely |
| CRED-016 | Constrained Delegation Abuse (S4U2Self/S4U2Proxy) | N/A | Service account delegation set | svc_web has TRUSTED_TO_AUTH_FOR_DELEGATION |
| CRED-017 | Resource-Based Constrained Delegation (RBCD) | N/A | Write to msDS-AllowedToActOnBehalfOfOtherIdentity | ws01$ allows svc_web$ |
| CRED-018 | Unconstrained Delegation Abuse | N/A | Service with TRUSTED_FOR_DELEGATION | file01 server unconstrained |
| CRED-019 | PrintNightmare Credential Dumping | CVE-2021-34527 | Unpatched Print Spooler | Print Spooler enabled, July 2021 patch missing |
| CRED-020 | PetitPotam NTLM Relay to ADCS | MS-EFSRPC | Domain user, ADCS present | EFSRPC unauthenticated, web enrollment allows NTLM |
| CRED-021 | DFSCoerce NTLM Relay | MS-DFSNM | Domain user, DFS namespace | DFS referral coercion |
| CRED-022 | PrinterBug / SpoolSample NTLM Relay | MS-RPRN | Domain user | Print spooler reachable from non-privileged user |
| CRED-023 | SamAccountName Spoofing (noPac) | CVE-2021-42278/42287 | Domain user, writable machine account | Machine account control, delegation present |
| CRED-024 | CVE-2022-26923 (Certifried/ESC22) | CVE-2022-26923 | ADCS web enrollment, user can enroll | HTTP + NTLM auth on CA web enrollment |
| CRED-025 | WebClient Service Abuse (PetitPotam Relay) | N/A | WebClient running on target | WebClient service installed and running |
| CRED-026 | AD IDNS Wildcard Poisoning | N/A | Any authenticated user | IDNS wildcards in AD DNS zones |
| CRED-027 | ADCS Disable SAN Validation (ESC22 variant) | N/A | ADCS web enrollment, NTLM relay | SAN not validated during enrollment |
| CRED-028 | ESC15 / CVE-2024-49019 | CVE-2024-49019 | ADCS with NTLM relay + DNS domain suffix | NTLM relay to ADCS web enrollment |
| CRED-029 | MS_Tag/SPN Hash Downgrade Negotiation | N/A | NTLM present, downgrade possible | NTLMSSP negotiation allows downgrades |
| CRED-030 | GPP Password Extraction (Groups.xml) | MS14-025 | SYSVOL access | Old GPP still present in SYSVOL |
| CRED-031 | AS-ROASTing (TGT for non-PA user) | N/A | No pre-auth users | User: no_preauth_svc |
| CRED-032 | Cleartext Protocol Interception (LDAP simple bind) | N/A | Network access | Some apps use LDAP simple bind on port 389 |
| CRED-033 | LAPS Password Read | N/A | Read to ms-Mcs-AdmPwd attribute | IT_Team has read on LAPS passwords |
| CRED-034 | gMSA Password Read | N/A | Read to msds-ManagedPassword | Helpdesk has read on gMSA password blob |
| CRED-035 | Credential Manager Saved Creds | N/A | Session hijack or local admin | Windows Credential Manager populated |
| CRED-036 | Browser Credential Extraction (mimikatz dpapi::) | N/A | Local admin | Chrome/Firefox saved passwords |
| CRED-037 | AzureAD SSO Token Extraction | N/A | PTA/PHS present | On-prem synced tenant |
| CRED-038 | Security Support Provider (SSP) Injection | N/A | Admin on box | Mimilib.dll SSP loaded |
| CRED-039 | SeBackupPrivilege -> SAM/SECURITY/NTDS | N/A | Backup Operators | Backup Operators membership |
| CRED-040 | SeTrustedCredManAccessPrivilege -> DPAPI | N/A | TrustedInstaller-like access | Privilege assigned to group |
| CRED-041 | SeDebugPrivilege -> LSASS | N/A | Admin/debug | Administrators have SeDebugPrivilege |
| CRED-042 | SeImpersonatePrivilege -> PrintNotifyPotato / RoguePotato | N/A | Low-priv user on server | Service accounts running as Network Service |
| CRED-043 | RID Hijacking (assign RID 500 to low-priv) | N/A | SYSTEM on workstation | Registry write access to SAM |
| CRED-044 | Hash Dump via VSS Admin Snapshot | N/A | Admin context | VSS service accessible |
| CRED-045 | DPAPI Master Key Theft | N/A | User context / SYSTEM | SYSTEM process extraction of DPAPI keys |
| CRED-046 | NTLMv2 Reflection with Responder | N/A | Poisoning possible | LLMNR/NBT-NS on, no DNS suffix |
| CRED-047 | Certificate Private Key Export (ESC12 variant) | N/A | Enrollment agent template | Vulnerable enrollment agent template |
| CRED-048 | NTLM Relay 2 LDAPS with Channel Binding Disabled | N/A | Network position or coercion | LDAP signing not enforced, channel binding off |
| CRED-049 | WebDAV Client Coercion -> Relay to LDAP | N/A | WebClient running + accessible | WebClient service auto-starts on triggered connection |
| CRED-050 | Zone Signing Key (ZSK) Leak -> DNS Forest Enumeration | N/A | DNSSEC zones | Misconfigured DNSSEC key storage |
| CRED-051 | .library-ms NTLM Hash Leak (archive UNC) | CVE-2025-24071 | User extracts crafted RAR/ZIP | Crafted `.library-ms` file with attacker UNC; Explorer auto-resolves -> NTLMv2 leak to Responder/SMB capture |
| CRED-052 | NTLM Relay via .library-ms vector | CVE-2025-33073 | Crafted archive + relay listener | `.library-ms` UNC -> ntlmrelayx -> LDAP/HTTP/SMB target |
| CRED-053 | ShadowCoerce (MS-FSRVP) | MS-FSRVP | DFSR / FSRVP enabled | FSRVP coercion of DC -> NTLM relay to ADCS / LDAP |
| CRED-054 | Pre-Windows 2000 Computer Account Abuse | N/A | Pre2k compatible objects present | Computer accounts with lowercase-name password (predictable) -> machine TGT -> S4U/RBCD/Silver |
| CRED-055 | RemoteMonologue (DCOM -> NTLMv2 capture) | N/A | DCOM enabled, low-priv access | DCOM trigger forces target to authenticate; Internal-Monologue captures NTLMv2 |
| CRED-056 | The Walking Dead — Disabled Account Abuse | N/A | GenericAll on disabled user | Re-enable disabled account with retained group memberships |
| CRED-057 | AD Recycle Bin — Deleted Object Restore | N/A | Write to deleted objects container | Restore deleted privileged object with original group memberships / sIDHistory |
| CRED-058 | gMSADumper (Read msDS-ManagedPassword) | N/A | PrincipalsAllowedToRetrieveManagedPassword | gMSADumper.py extracts NT hash blob -> PtH |
| CRED-059 | goLAPS / LAPS v2 Bulk Read | N/A | ReadLAPSPassword extended right | Helpdesk delegated bulk LAPS read across OU |
| CRED-060 | SCCMDecryptor-BOF (DPAPI on SCCM client) | N/A | Local admin on SCCM-managed host | Decrypts SCCM NAA / policy secrets in CIM/WMI repository |
| CRED-061 | Kerberos Relay via CNAME (krbrelayx) | N/A | DNS write or ADIDNS | Register CNAME -> victim auth -> relay Kerberos to LDAP |
| CRED-062 | Reflective Kerberos Relay | N/A | Same-host relay possible | krbrelayx reflects Kerberos auth back to issuer service |
| CRED-063 | MS14-068 PAC Forgery (legacy) | CVE-2014-6324 | Unpatched DC (lab-injected for chain) | Forge PAC -> any user becomes DA |
| CRED-064 | Internal-Monologue (NetNTLMv1 downgrade) | N/A | LMCompatibilityLevel <= 2 on host | Force NetNTLMv1 -> trivial crack |
| CRED-065 | DPAPI Master Key Theft (Remote) | N/A | SYSTEM or DPAPI backup key | Pull domain DPAPI backup key from DC; decrypt any user's masterkey offline |

### Phase 3: Lateral Movement (Flags LAT-001 to LAT-035)

| ID | Technique | Ref | Pre-condition | Vuln Config |
|----|-----------|-----|---------------|-------------|
| LAT-001 | PsExec with Pass-the-Hash | N/A | Admin hash + ADMIN$ share | ADMIN$ accessible to Domain Admins |
| LAT-002 | WMI Exec (wmiexec) | N/A | Admin creds/hash | WMI allowed over network |
| LAT-003 | Scheduled Task (schtasks /create /s /ru) | N/A | Admin on target | Remote scheduled task creation allowed |
| LAT-004 | Service Creation (sc create / sc start) | N/A | Admin on target | Services remotely manageable |
| LAT-005 | DCOM Execution (MMC20.Application) | N/A | Admin on target | DCOM enabled, MMC accessible |
| LAT-006 | WinRM Remote Shell (Enter-PSSession) | N/A | Valid creds + WinRM listener | WinRM enabled broadly |
| LAT-007 | RDP with Pass-the-Hash (Restricted Admin) | N/A | Hash + RDP enabled | Restricted Admin mode enabled |
| LAT-008 | Remote Registry Modification | N/A | Admin on target | Remote registry service running |
| LAT-009 | SMB Pipe Exec (atsvc, svcctl) | N/A | Admin/hash | Named pipes accessible |
| LAT-010 | SSH Tunneling through Domain Trust | N/A | SSH server on target | OpenSSH server installed on file server |
| LAT-011 | Certificate-Based Authentication Relay | ADCS ESC | Valid cert from ESC1 | ESC1 template allows domain user enrollment |
| LAT-012 | Cross-Forest SID History Abuse | N/A | Enterprise Admin / trust hop | SID Filtering disabled on external trust |
| LAT-013 | Shortcut Trust Abuse | N/A | Shortcut trust to far OU | Realm trust: contractor.corp |
| LAT-014 | Realm Trust MIT Kerberos Relay | N/A | Realm trust, MIT present | RC4 enabled on realm trust |
| LAT-015 | IPv6 DHCPv6 MitM + WPAD Relay | N/A | IPv6 enabled, no RA guard | IPv6 enabled by default, no DHCPv6 guard |
| LAT-016 | Resource-Based Constrained Delegation Chain | N/A | Chain of delegation hops | Multiple servers with RBCD configured |
| LAT-017 | ACL Abuse: ForceChangePassword | N/A | GenericWrite on user | Helpdesk has GenericWrite on Domain Users |
| LAT-018 | ACL Abuse: Add Members on Group | N/A | GenericWrite on group | IT_Admins writable by Helpdesk |
| LAT-019 | ACL Abuse: Add KeyCredentialLink | N/A | GenericWrite on target | msDS-KeyCredentialLink writable |
| LAT-020 | ACL Abuse: Owner Change | N/A | WriteOwner on target | Helpdesk has WriteOwner on Domain Admins |
| LAT-021 | ACL Abuse: DCSync via GenericAll on domain | N/A | GenericAll/WriteDACL on domain object | Sync_Account delegated GenericAll on domain |
| LAT-022 | ACL Abuse: WriteSPN -> Kerberoast | N/A | Validated-SPN write | svc_generic has validated-SPN write on other accounts |
| LAT-023 | Cross-Forest TGT Delegation Abuse | N/A | Trust with TGT delegation | External trust allows TGT delegation |
| LAT-024 | LDAP Signing Not Required -> Relay to Any DC | N/A | LDAP signing missing | ldap_server_integrity not enforced |
| LAT-025 | WebDAV Redirector Coercion (Coerce Authentication) | N/A | srvsvc / webdav redirector | srvsvc pipe triggers auth to attacker |
| LAT-026 | KrbRelayUp (Local Privilege Escalation via Kerberos relay) | N/A | Low-priv domain user on host | Default RBCD write to local machine account; relay to local LSASS pipe |
| LAT-027 | mitm6 (DHCPv6 -> WPAD -> NTLM Relay) | N/A | IPv6 stack enabled, no RA Guard | mitm6 poisons DHCPv6 to deliver malicious DNS/WPAD; victim auths to attacker -> ntlmrelayx -> LDAP/LDAPS |
| LAT-028 | LLMNR + SMB Relay to Workstation (no SMB signing) | N/A | SMB signing off, LLMNR on | Responder captures -> ntlmrelayx -c "..." -smb2support |
| LAT-029 | SCShell (Service-Based Lateral Execution) | N/A | Admin-equivalent on target | Modify existing service binPath remotely -> service start -> exec |
| LAT-030 | RDP Session Hijack (tscon / SYSTEM context) | N/A | SYSTEM on target RDP host | Hijack disconnected RDP sessions of admins for credential reuse |
| LAT-031 | DnsAdmins -> DLL Load on DC | N/A | Membership in DnsAdmins | dnscmd /config /ServerLevelPluginDll attacker.dll; restart DNS -> SYSTEM on DC |
| LAT-032 | ADIDNS Record Write (Authenticated Users) | N/A | Authenticated Users can create DNS records | Hijack wpad / file server names via AD-integrated DNS -> intercept auth |
| LAT-033 | LNK / SCF / URL File Drop on writable share | N/A | Write access to a heavily-browsed share | Drop .lnk/.scf with attacker UNC; users browsing trigger NTLM auth |
| LAT-034 | Foreign Group Membership (cross-forest) | N/A | One-way trust with FSP added | FSP from finance.local placed into corp.local privileged group |
| LAT-035 | Cross-Forest via Golden + SID History (RID > 1000) | N/A | Own trusted forest, krbtgt hash | Forge golden ticket with foreign SIDs (RID > 1000 to bypass SID filtering on some configs) |

### Phase 4: Privilege Escalation (Flags PE-001 to PE-060)

| ID | Technique | CVE/Ref | Pre-condition | Vuln Config |
|----|-----------|---------|---------------|-------------|
| PE-001 | SeImpersonatePrivilege -> JuicyPotato / RoguePotato / GodPotato | N/A | Low priv on server | IIS AppPool, SQL Services running as Network Service |
| PE-002 | SeAssignPrimaryTokenPrivilege -> CreateProcessAsUser | N/A | Privilege present | Rare privilege, assigned to custom group |
| PE-003 | SeTcbPrivilege -> Trusted Computing Base | N/A | SYSTEM-level privilege | Logon scripts assigned |
| PE-004 | SeLoadDriverPrivilege -> Capcom / EOPLOD / HEVD | N/A | Win10 workstation | Capcom.sys or HEVD signed driver |
| PE-005 | SeBackupPrivilege -> File Read Bypass ACLs | N/A | Backup Operators | Backup Operators group populated |
| PE-006 | SeRestorePrivilege -> File Write Bypass ACLs | N/A | Backup Operators | Same as above |
| PE-007 | Unquoted Service Path (Program.exe) | N/A | Write to C:\ or service dir | Service: VulnService path unquoted |
| PE-008 | Weak Service ACL (Everyone:F on service registry) | N/A | Write to service registry key | Service DACL allows Everyone:ChangeConfig |
| PE-009 | DLL Hijacking (KnownDlls / Path / Search Order) | N/A | Write to binary dir or PATH | Custom app with missing DLL in writable path |
| PE-010 | PATH Hijacking (Write to user/system PATH first) | N/A | Write to PATH dir | PATH includes C:\Tools (writable) |
| PE-011 | AlwaysInstallElevated MSI | N/A | HKLM/HKCU policy enabled | AlwaysInstallElevated = 1 in both hives |
| PE-012 | UAC Bypass (FodHelper / ComputerDefaults / sdclt) | N/A | Admin user, UAC default | Default UAC on admin account |
| PE-013 | Token Kidnapping (churrasco.exe) | Legacy | SeImpersonate + named pipe | Classic potato vector |
| PE-014 | Named Pipe Impersonation (PrintSpooler / RoguePotato) | N/A | SeImpersonate on server | Custom pipe service: pipe_svc.exe |
| PE-015 | Service Control Manager (services.exe) Overwrite | N/A | Self-restore point reach | Misconfigured system privileges |
| PE-016 | Task Scheduler Race Condition | N/A | Write to task directory | Scheduled task XML writable by Users |
| PE-017 | Privilege Escalation via COM Objects (PrintNotify) | N/A | SeImpersonate | PrintNotification COM service |
| PE-018 | GPO Application on Insecure Share (SYSVOL permissions) | N/A | Write to GPO folder | GPO scripts folder writable by Authenticated Users |
| PE-019 | Backup Operators -> Modify GPO/flag files | N/A | Backup Operators | Backup Operators has write to C:\Flags via GPO |
| PE-020 | SeChangeNotifyPrivilege (traverse folder) | N/A | Standard user | Hidden folder traversal allowed |
| PE-021 | SeIncreaseQuotaPrivilege -> New AD Object Creation | N/A | Admin context | Create new privileged object |
| PE-022 | Scheduled Task Hijack (Overwrite existing .job) | N/A | Write to %windir%\Tasks | .job files writable by Users |
| PE-023 | Startup Folder Persistence / Escalation | N/A | Write to startup folder | All Users Startup writable by Domain Users |
| PE-024 | CVE-2021-36934 (HiveNightmare / SeriousSAM) | CVE-2021-36934 | Unpatched Win10/Server | BUILTIN\Users can read VSS snapshots |
| PE-025 | Token Privilege Exploitation Suite | N/A | Any token privilege available | Custom vulnerable binary with each privilege |
| PE-026 | SeManageVolumePrivilege + Windows Installer Exploit | N/A | SeManageVolumePrivilege | VulnLocked: Abuse junctions with mountmgr |
| PE-027 | SeCreateSymbolicLinkPrivilege + Junction Exploits | N/A | Developer group assigned | Symbolic link creation allowed |
| PE-028 | SeDebugPrivilege -> Token Stealing from LSASS | N/A | Debug privilege | Administrator has SeDebugPrivilege |
| PE-029 | SeTakeOwnershipPrivilege -> Take Ownership of Files | N/A | Rare privilege, but present | Custom group: Asset_Owners |
| PE-030 | Service Binary Replacement | N/A | DACL allows write/change | Service binary writable by Users |
| PE-031 | CVE-2022-30190 (Follina MS-MSDT) | CVE-2022-30190 | Word doc / link opening | MSDT protocol handler enabled |
| PE-032 | CVE-2023-21716 (WordPad RCE via RTF) | CVE-2023-21716 | WordPad processing | WordPad installed and unpatched |
| PE-033 | CVE-2023-28252 (CLFS EoP) | CVE-2023-28252 | Low-priv on system | CLFS driver unpatched |
| PE-034 | CVE-2023-36745 (WinSockAFD LPE) | CVE-2023-36745 | Low-priv on system | AFD.sys unpatched |
| PE-035 | CVE-2023-29360 (Windows TrustedInstaller LPE) | CVE-2023-29360 | Low-priv on system | Unpatched system |
| PE-036 | CVE-2024-20673 / CVE-2024-20674 (Windows LPEs) | CVE-2024-2067x | Various | Unpatched 2024 system |
| PE-037 | CVE-2024-26229 (Windows CSC Service LPE) | CVE-2024-26229 | Low-priv user | CSC service present |
| PE-038 | CVE-2024-30051 (DWM Core Library LPE) | CVE-2024-30051 | Graphical session | DWM unpatched |
| PE-039 | CVE-2024-38063 (TCP/IP IPv6 RCE->LPE) | CVE-2024-38063 | IPv6 processing | Unpatched 2024 |
| PE-040 | CVE-2025-XXXX placeholder for future LPEs | N/A | N/A | Lab will be updated monthly |
| PE-041 | Modifiable Service Path to Folder | N/A | Parent folder writable | Service path folder modifiable |
| PE-042 | Modifiable Registry Path | N/A | Registry key writable | Service ImagePath registry key writable by Users |
| PE-043 | StorSvc Abuse (Ssms.exe / LOLBAS) | N/A | SeImpersonate | StorSvc trigger |
| PE-044 | CDPSvc / Connected Devices Platform Abuse | N/A | Low-priv user | CDPSvc running with SYSTEM |
| PE-045 | Perfmon / Resource Monitor Escalation | N/A | Low-priv user | Help key triggers cmd.exe |
| PE-046 | CVE-2022-38047 (Windows Point and Print EoP) | CVE-2022-38047 | Print spooler present | Unpatched |
| PE-047 | CVE-2022-44676 / CVE-2022-44670 (Windows LPE) | CVE-2022-446xx | Low-priv | Unpatched 2022 |
| PE-048 | CVE-2022-33647 (Kerberos S4U2Self LPE) | CVE-2022-33647 | Service account | Unpatched 2022 |
| PE-049 | Third-Party Driver EoP (RTCore64.sys / MSI Afterburner) | MSI driver | Low-priv | Vulnerable signed driver present |
| PE-050 | Windows Installer Repair Mode Escalation | N/A | Low-priv with msi access | MSI repair mode triggers SYSTEM cmd |
| PE-051 | KrbRelayUp (Local Kerberos Relay -> Local Admin) | N/A | Any domain user on Windows host | Default LSASS pipe + machine-account RBCD write enabled |
| PE-052 | Potato Suite Detailed (Juicy / Rogue / God / PrintSpoofer / SweetPotato / CertPotato / DCOMPotato / RemotePotato0) | N/A | SeImpersonatePrivilege | Service runs as Network Service / IIS AppPool / SQL Service |
| PE-053 | CertPotato (ADCS-based SYSTEM via S4U) | N/A | SeImpersonate + ADCS reachable | Service token + machine account cert auth -> SYSTEM |
| PE-054 | NetExec local-auth admin sweep | N/A | LAPS not deployed | Same local admin password reused (golden image) |
| PE-055 | CVE-2025-XXXX Yearly LPE placeholder | TBD | Updated monthly | Track 2025 Windows LPE CVEs |
| PE-056 | UAC Bypass via WSReset.exe / DiskCleanup / EventViewer / Cmstp.exe | N/A | Medium IL, admin user | Default UAC + auto-elevate binaries present |
| PE-057 | Server Operators -> SYSTEM (sc create on DC) | N/A | Member of Server Operators on DC | Misuse: change Service binPath for any service on DC -> SYSTEM |
| PE-058 | Print Operators -> Driver Install -> Code Exec on DC | N/A | Member of Print Operators | Print driver install = SYSTEM on DC |
| PE-059 | Backup Operators on DC -> NTDS.dit theft | N/A | Member of Backup Operators on DC | Use SeBackupPrivilege to read NTDS.dit + SYSTEM hive |
| PE-060 | TrustedInstaller -> SYSTEM (Tier 0 boundary) | N/A | Admin on host | psexec -s -i to switch to TrustedInstaller context |

### Phase 5: Persistence (Flags PER-001 to PER-037)

| ID | Technique | Ref | Path | Vuln Config |
|----|-----------|-----|------|-------------|
| PER-001 | Registry Run Keys (HKLM/HKCU Run) | N/A | Admin / user write | C:\Temp\persistence.exe in HKLM Run |
| PER-002 | Image File Execution Options (IFEO Debugger) | N/A | Admin write | IFEO set on sethc.exe, utilman.exe |
| PER-003 | Sticky Keys / Utilman Hijack | N/A | Offline or pre-auth | sethc.exe replaced with cmd.exe |
| PER-004 | Windows Service Installation | N/A | Admin write | PersistenceService.exe registered |
| PER-005 | Scheduled Task (AtStartup / OnIdle) | N/A | Admin write | Task: UpdaterService runs beacon |
| PER-006 | WMI Event Subscription | N/A | Admin write | __EventFilter + __EventConsumer |
| PER-007 | Netsh Helper DLL | N/A | Admin write | netsh add helper DLL added |
| PER-008 | COM Hijacking (TreatAs / ProgID) | N/A | HKCR write | COM key redirected to evil DLL |
| PER-009 | Authentication Package (LsaAdd/lsaap.dll) | N/A | SYSTEM | Custom LSA AP registered |
| PER-010 | Time Providers (W32Time) | N/A | Admin | W32Time DLL hijack |
| PER-011 | BootExecute / SetupExecute | N/A | Admin / SYSTEM | AutoChk command modified |
| PER-012 | AppInit_DLLs | N/A | Admin | AppInit_DLLs enabled, DLL loaded into every process |
| PER-013 | Accessibility Tools Backdoor | N/A | Admin/System | All accessibility tools replaced |
| PER-014 | RID Hijacking (SAM modification) | N/A | SYSTEM / Offline | User hacker has RID 500 |
| PER-015 | AdminSDHolder Abuse | N/A | Modify AdminSDHolder | AdminSDHolder ACL grants full control to new group |
| PER-016 | SID History Injection | N/A | Domain Admin / Schema Admin | Add Enterprise Admin SID to account |
| PER-017 | DCShadow (persistent rogue DC) | N/A | Write to Configuration NC | Re-register rogue DC periodically |
| PER-018 | Golden Ticket Persistence | N/A | KRBTGT hash | Skip verification with known hash |
| PER-019 | Silver Ticket Persistence | N/A | Service account hash | Forge ticket for persistence |
| PER-020 | Skeleton Key (mimikatz) | N/A | Domain Admin | misc::skeleton on DC |
| PER-021 | Diamond Ticket | N/A | krbtgt hash + legitimate user TGT | Decrypt real TGT with krbtgt, modify PAC (Administrator) — legitimate 4768 event on DC, stealthier than Golden |
| PER-022 | Sapphire Ticket (S4U2Self + U2U PAC) | N/A | krbtgt hash | Real PAC obtained via S4U2Self+U2U injected into modified TGT — most stealthy variant |
| PER-023 | Golden Certificate (CA Private Key Theft) | N/A | DA on CA / SYSTEM on CA | `certipy ca -backup` exports CA cert + private key; forge cert for any user; survives password resets / krbtgt rotations |
| PER-024 | Custom Security Support Provider (memssp / mimilib) | N/A | Local Admin / SYSTEM on DC | Register evil DLL in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`; captures plaintext on every auth -> mimilsa.log |
| PER-025 | DSRM Backdoor (Directory Services Restore Mode) | N/A | DA on DC | Set `DsrmAdminLogonBehavior=2` -> network logon with DSRM hash; PtH directly to DC |
| PER-026 | Authentication Package Persistence (LsaAddAuthenticationPackage) | N/A | SYSTEM | Custom auth package DLL loaded by LSASS each boot |
| PER-027 | KeyCredentialLink Persistence (Self-Shadow Creds) | N/A | GenericWrite on own account | Add persistent device key to msDS-KeyCredentialLink; auth as user via PKINIT forever |
| PER-028 | gMSA Backdoor (delegated read) | N/A | DA | Add attacker to PrincipalsAllowedToRetrieveManagedPassword on a privileged gMSA |
| PER-029 | RBCD Persistence (machine account ownership) | N/A | DA / WriteDACL | Set msDS-AllowedToActOnBehalfOfOtherIdentity on DC for attacker-owned machine account |
| PER-030 | ADIDNS Time Bomb (pre-staged records) | N/A | Authenticated Users can create DNS records | Pre-register DNS names for future hosts (e.g., new-fileserver.corp.local) -> MITM on first auth |
| PER-031 | Schema Modification Backdoor | N/A | Schema Admins | Add malicious attribute / class that grants implicit privileges |
| PER-032 | Hidden Account via Confidentiality Flag | N/A | DA | Set object security descriptor so it doesn't appear in normal enumeration |
| PER-033 | AdminSDHolder ACL Injection | N/A | DA / WriteDACL on AdminSDHolder | Add attacker ACE; SDProp re-applies to every protected object every 60 min (self-healing) |
| PER-034 | GPO Backdoor (SharpGPOAbuse / SYSVOL write) | N/A | DA / Edit on GPO | Inject scheduled task / startup script via GPO -> code on every machine in OU |
| PER-035 | RODC Compromise Persistence | N/A | RODC admin | Add accounts to msDS-RevealOnDemandGroup; passwords cached on RODC permanently |
| PER-036 | Machine Account Persistence (MachineAccountQuota = 10) | N/A | Any user | Create up to 10 attacker-owned machine accounts for RBCD even after main account is disabled |
| PER-037 | Confidential Service Account with TRUSTED_FOR_DELEGATION | N/A | DA | Create privileged service account with unconstrained delegation as long-term coercion target |

### Phase 6: Domain/Forest Compromise (Flags DF-001 to DF-040)

| ID | Technique | CVE/Ref | Pre-condition | Vuln Config |
|----|-----------|---------|---------------|-------------|
| DF-001 | Golden Ticket (krbtgt forge) | N/A | DCSync krbtgt hash | User runs DCSync, forges TGT |
| DF-002 | Silver Ticket (service account forge) | N/A | Service account hash | Forge TGS for CIFS or HOST SPN |
| DF-003 | DCSync All Hashes | N/A | DCSync rights | Full credential dump |
| DF-004 | DCShadow Attack | N/A | Replication rights | Create rogue DC, push changes |
| DF-005 | SID-History Injection (Forest compromise) | N/A | Enterprise Admin / Schema Admin | Inject EA SID into account |
| DF-006 | Trust Ticket Abuse (Inter-realm TGT) | N/A | Cross-forest trust | Forge inter-realm TGT |
| DF-007 | ExtraSID Attack (Parent-Child) | N/A | Child domain admin | RID 519/512 from parent |
| DF-008 | SID Filtering Bypass (sIDHistory) | N/A | External trust | Disable SID filtering, inject SID |
| DF-009 | Foreign Security Principal Hijack | N/A | Trust present | Add FSP to privileged group |
| DF-010 | Cross-Forest Kerberoasting | N/A | Cross-forest SPNs | SPNs on foreign security principals |
| DF-011 | ADCS Domain Admin ESC8 (Web Enrollment NTLM Relay) | ESC8 | ADCS web enrollment + NTLM relay | Web enrollment on HTTP, no EPA |
| DF-012 | ADCS Domain Admin ESC1 (Template SID injection) | ESC1 | Vulnerable template | Domain Users can enroll, EKU for client auth, no approval |
| DF-013 | ADCS Domain Admin ESC2 (EKU Any Purpose) | ESC2 | Template EKU=Any Purpose | Any purpose + client auth |
| DF-014 | ADCS Domain Admin ESC3 (Agent Template) | ESC3 | Enrollment agent cert | Get Agent cert -> enroll on behalf of anyone |
| DF-015 | ADCS Domain Admin ESC4 (Vulnerable ACL on Template) | ESC4 | GenericAll/WriteDACL on template | Domain Users have GenericAll on template |
| DF-016 | ADCS Domain Admin ESC5 (Vulnerable PKI Object ACL) | ESC5 | Write to CA registry / config | PKI container writable |
| DF-017 | ADCS Domain Admin ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) | ESC6 | User SAN in all certs | SAN2 flag set on CA |
| DF-018 | ADCS Domain Admin ESC7 (Manager/Officer role abuse) | ESC7 | Cert Manager / Officer role | Low-priv manager can approve requests |
| DF-019 | ADCS ESC8 (ADCS relay Web Enrollment) | ESC8 | HTTP web enrollment, no EPA | Web enrollment on HTTP, no Extended Protection |
| DF-020 | ADCS ESC9 (No Security Extension + Specified Certificate) | ESC9 | Template: NoSecExt + SpecifiedCert | Vulnerable combination |
| DF-021 | ADCS ESC10 (Weak DACL on CA Reg / Cert Publishers) | ESC10 | Writable CA reg / group | Misconfigured ACL on CA object |
| DF-022 | ADCS ESC11 (Weak DACL on NTLM Relay to ICPR) | ESC11 | Newer ADCS equivalent | ADCS >= 2016 with misconfig |
| DF-023 | Child Domain -> Enterprise Admin (no SID filtering) | N/A | Full mesh trust topology | SID filtering disabled |
| DF-024 | sAMAccountName spoofing -> noPac | CVE-2021-42278 | Machine account control | machine$ renamed, Silver ticket |
| DF-025 | CVE-2022-26923 Certifried | CVE-2022-26923 | ADCS web enrollment + DNS dNSHostName | Web enrollment + NTLM relay |
| DF-026 | CVE-2022-33647 (Kerberos S4U2Self LPE to EoP chain) | CVE-2022-33647 | Unpatched systems | Chain to full domain admin |
| DF-027 | SAMAccountName to EnterpriseAdmin via Trust | N/A | Cross-domain trust + noPac | Rename + ticket across trust |
| DF-028 | Read Only DC Abuse (Password Replication Policy) | N/A | RODC compromise | Passwords revealed on RODC |
| DF-029 | GPO Delegation to Domain Admin | N/A | Edit GPO via delegation | Low-priv delegated group edits GPO |
| DF-030 | Schema Admin Hijack | N/A | Schema Admin membership | Add malicious schema attribute |
| DF-031 | ADCS ESC13 (Issuance Policy -> Group) | ESC13 | Vulnerable issuance policy linked to privileged group | Template with OID-linked issuance policy mapped to msDS-OIDToGroupLink-targeted group |
| DF-032 | ADCS ESC14 (Explicit Certificate Mapping) | ESC14 | DA / SYSTEM on CA + altSecurityIdentities writable | Explicit cert mapping on victim AD object grants impersonation |
| DF-033 | ADCS ESC15 (EKUwu / Schema v1 App Policy) | CVE-2024-49019 | Schema v1 template + enrollment | `certipy req` with custom Application Policy OID -> SAN Administrator -> DA |
| DF-034 | ADCS ESC16 (CA-wide No Security Extension) | ESC16 | DA / SYSTEM on CA registry | DisableExtensionList includes szOID_NTDS_CA_SECURITY_EXT -> all issued certs vulnerable |
| DF-035 | ZeroLogon (CVE-2020-1472) | CVE-2020-1472 | Network access to DC, unpatched Netlogon | Empty machine secret on DC -> DCSync -> DA (caveat: breaks replication) |
| DF-036 | MS14-068 Forged PAC | CVE-2014-6324 | Unpatched DC (lab-injected) | Domain user -> forged PAC TGS -> any group SID -> DA |
| DF-037 | Cross-Forest Trust Ticket (Inter-Realm with EA SID) | N/A | krbtgt for trusted forest + SID History injection | Inject Enterprise Admin SID (S-1-5-21-...-519) via inter-realm TGT across external trust |
| DF-038 | Foreign Group Membership Privilege Escalation | N/A | One-way external trust | Add FSP from finance.local into corp.local Domain Admins |
| DF-039 | SCCM Site Takeover (NAA -> NTLM Relay -> Full Admin) | N/A | SCCM deployed with NAA + HTTP MP | sccmhunter NAA harvest + push coerce + relay to MSSQL site DB |
| DF-040 | Diamond + Sapphire Ticket forest persistence | N/A | krbtgt across forest | Same as PER-021/022 but applied cross-forest to maintain EA |

---

## 4. VM Manifest & Sizing

| VM Name | Hostname | OS | Role | vCPU | RAM | Disk | Network |
|---------|----------|-----|------|------|-----|------|---------|
| DC01-CORP | dc01.corp.local | Windows Server 2022 Core | Primary DC, DNS, ADCS | 2 | 3072 MB | 40 GB | virbr1 |
| DC01-EU | dc01.eu.corp.local | Windows Server 2022 Core | Child DC | 1 | 2048 MB | 25 GB | virbr1 |
| CA01 | ca01.corp.local | Windows Server 2022 Core | Enterprise CA | 1 | 2048 MB | 25 GB | virbr1 |
| FILE01 | file01.corp.local | Windows Server 2022 Core | File Server | 1 | 1536 MB | 20 GB | virbr1 |
| SQL01 | sql01.corp.local | Windows Server 2022 Core | MSSQL Server | 1 | 2048 MB | 25 GB | virbr1 |
| WS01 | ws01.corp.local | Windows Server 2022 Core | Victim Workstation (phishing landing, lateral target) | 2 | 3072 MB | 30 GB | virbr1 |
| DC01-FIN | dc01.finance.local | Windows Server 2022 Core | External Forest DC | 1 | 2048 MB | 25 GB | virbr2 |
| DC01-ROOT | dc01.root.corp | Windows Server 2022 Core | Root Forest DC | 1 | 2048 MB | 25 GB | virbr3 |

**Total Footprint:** ~12 vCPUs, ~18 GB RAM, ~215 GB disk (thin-provisioned QCOW2 ~60 GB actual)

---

## 5. Network Design

### 5.1 QEMU Network Architecture

```
+-----------------------------------------------------------+
|                       HOST NODE (Proxmox)                  |
|                                                            |
|  +---------------+    +---------------+    +-------------+  |
|  | virbr0 (NAT)  |    | virbr1 (CTF)  |    | virbr2      |  |
|  | 10.0.2.0/24   |    | 10.10.0.0/21  |    | 10.20.0/24  |  |
|  +-------+-------+    +-------+-------+    +-----+-------+  |
|          |                    |                  |          |
|          |    +---------------+------------------+----+      |
|          |    |                                       |      |
|    +-----v----v------+                         +------v--+   |
|    |   Router VM     |                         | virbr3  |   |
|    |   (Alpine Linux)|                         |10.30.0/24|  |
|    +--------+--------+                         +----+----+   |
|             |                                       |       |
|    +--------v--------+                         +----v----+   |
|    | Internet Access  |                         | ROOT.CORP |  |
|    | (NAT forwarding) |                         +-----------+  |
|    +------------------+                                       |
+---------------------------------------------------------------+
```

### 5.2 VLAN / Subnet Allocation

| Network | Subnet | Purpose | Security |
|---------|--------|---------|----------|
| virbr1 | 10.10.0.0/21 | Primary CTF lab network | Isolated LAN, no outbound except DNS/NTP |
| virbr2 | 10.20.0.0/24 | Finance forest network | External trust segment |
| virbr3 | 10.30.0.0/24 | Root forest network | Tree-root trust segment |
| virbr0 | 10.0.2.0/24 | NAT / management | Host bridge for internet (install time only) |

### 5.3 Static IP Assignment

| VM | NIC1 (virbr1) | NIC2 (virbr2) | NIC3 (virbr3) | Gateway | DNS |
|----|---------------|---------------|---------------|---------|-----|
| dc01.corp.local | 10.10.0.10 | - | - | 10.10.0.1 | 10.10.0.10 |
| dc01.eu.corp.local | 10.10.0.11 | - | - | 10.10.0.1 | 10.10.0.10 |
| ca01.corp.local | 10.10.0.12 | - | - | 10.10.0.1 | 10.10.0.10 |
| file01.corp.local | 10.10.0.13 | - | - | 10.10.0.1 | 10.10.0.10 |
| sql01.corp.local | 10.10.0.14 | - | - | 10.10.0.1 | 10.10.0.10 |
| ws01.corp.local | 10.10.0.100 | - | - | 10.10.0.1 | 10.10.0.10 |
| dc01.finance.local | - | 10.20.0.10 | - | 10.20.0.1 | 10.20.0.10 |
| dc01.root.corp | - | - | 10.30.0.10 | 10.30.0.1 | 10.30.0.10 |

---

## 6. Deployment Architecture

### 6.1 Build Pipeline

```
+------------------+     +-------------------+     +------------------+
|  Host OS         | --> |  setup-deps.sh    | --> |  QEMU/KVM        |
|  (Linux any)     |     |  (auto-detection) |     |  configured      |
+------------------+     +-------------------+     +--------+---------+
                                                             |
+------------------------------------------------------------+
|  Phase 1: Network Setup (qemu/network/setup-network.sh)
|  - Creates virbr1, virbr2, virbr3
|  - Configures NAT via iptables/nftables
|  - Sets up DHCP + DNSMasq for bootstrapping
|
|  Phase 2: Windows Media Download (scripts/download-windows.ps1 + scripts/download-fod.sh)
|  - Detects architecture
|  - Downloads Windows Server 2022 Eval ISO from Microsoft eval center
|  - Downloads FOD ISO for optional components
|  - Mounts ISO and creates install source tree
|
|  Phase 3: VM Creation (qemu/vm-create.sh)
|  - QEMU-img create thin-provisioned QCOW2s
|  - Injects autounattend.xml (cloud-init variant for QEMU)
|  - Starts VMs with virtio drivers
|  - Boots from ISO, auto-installs Core
|
|  Phase 4: Post-Install MassGrave Activation (scripts/massgrave-activate.ps1)
|  - Downloads massgrave.dev activation script
|  - Activates all Windows Server instances
|
|  Phase 5: Ansible Hardening & Vuln Injection (ansible/playbooks/site.yml)
|  - Configures AD DS / child domains / trusts
|  - Installs ADCS with vulnerable templates
|  - Injects all PE vulnerabilities
|  - Places flags and configures ACLs
|  - Deploys verification listener
|
|  Phase 6: Verification & Snapshots (scripts/finalize.sh)
|  - Sanity check all flags reachable via correct vectors
|  - Create QEMU snapshots for reset capability
|  - Generate participant handout
+-------------------------------------------------------------+
```

---

## 7. OS Media Strategy

### 7.1 Official Microsoft Sources (No Redistribution)

| Component | URL | Size | Alternative |
|-----------|-----|------|-------------|
| Windows Server 2022 Eval ISO | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 | ~4.9 GB | Direct download via MediaCreationTool wrapper |
| Windows Server 2022 Core | Same ISO (index 2) | ~2.8 GB installed | Use DISM to extract Core index |
| FOD ISO | Same eval center | ~1.2 GB | Downloaded on demand |
| VirtIO Drivers | https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/ | ~400 MB | Latest stable ISO |

### 7.2 Automated Download Script

The download-windows script will:
1. Detect host OS and architecture (x86_64 / aarch64)
2. Check if aria2c, curl, or wget is available
3. Download the ISO if not already present in media/
4. Verify SHA256 checksum (embedded in script)
5. Mount ISO loopback to extract install.wim
6. Select Server Core index for QEMU deployment

### 7.3 Trimming Strategy for Lightweight VMs

Using Windows Server Core reduces base footprint from ~10 GB to ~2.8 GB. Additional trimming:
- Remove language packs (keep en-US only)
- Remove unused Windows roles/features
- Disable Hibernation, PageFile tuning
- Run dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
- Compact VHD after Sysprep before QCOW2 conversion

---

## 8. Activation Strategy

Using **Massgrave.dev** activation:
1. Each VM post-install runs a PowerShell one-liner downloading get.ps1 from massgrave
2. Executes HWID/KMS38 activation for Windows Server
3. All activations are temporary and lab-local only
4. No license key is stored or redistributed

**Script:**
```powershell
$null = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2 -PropertyType DWord -Force
Invoke-RestMethod https://massgrave.dev/get | Invoke-Expression
```

---

## 9. Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| ISO unavailable | Build failure | Mirrors: Archive.org, official Microsoft CDN links |
| Activation blocked | Lab stops working | KMS38/HWID via massgrave, can be re-run anytime |
| TrustedInstaller hardening blocks PE | Techniques fail | Disable Windows Defender, Tamper Protection, Reputation-based protection |
| Network conflicts with host | Host disruption | Complete network isolation, NAT only during install phase |
| Escape to host via QEMU | Host compromise | Use unprivileged QEMU user session, AppArmor/SELinux profiles |
| Evaluation license expiration | Lab unusable | KMS38 activation resets timer; or auto-rearm scripts |
| AV/Mitigations block exploits | CTF failure | Disable: ASLR, CFG, DEP for targeted binaries; real mitigations left on for realistic scenarios |
| Too large for single host | Resource exhaustion | VMs can be split across two Proxmox nodes with VXLAN |

---

## 10. Research Sources & References

### Primary Sources
1. **BloodHound / SharpHound** - https://github.com/BloodHoundAD/BloodHound
2. **Microsoft AD Security Best Practices** - https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices
3. **ADSecurity.org (Sean Metcalf)** - https://adsecurity.org/
4. **HarmJ0y's Blog** - https://www.harmj0y.net/blog/
5. **SpecterOps Posts** - https://posts.specterops.io/
6. **Dirk-jan Mollema's Research** - https://dirkjanm.io/
7. **Certified Pre-Owned (ADCS Attacks)** - https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
8. **GhostPack / PowerSploit** - https://github.com/GhostPack
9. **LOLBAS Project** - https://lolbas-project.github.io/
10. **Privilege Escalation - Windows Local** - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

### CVE Tracker
- **2021:** PrintNightmare (CVE-2021-34527), noPac (CVE-2021-42278/42287), HiveNightmare (CVE-2021-36934)
- **2022:** Follina (CVE-2022-30190), Certifried (CVE-2022-26923), Windows LPEs (CVE-2022-446xx, -33647, -38047)
- **2023:** WordPad RCE (CVE-2023-21716), CLFS EoP (CVE-2023-28252), AFD.sys (CVE-2023-36745)
- **2024:** Windows LPEs (CVE-2024-2067x, -26229, -30051), ESC15 (CVE-2024-49019), TCP/IP (CVE-2024-38063)
- **2025:** To be tracked and updated monthly

### Exploit Framework References
1. **Mimikatz** - benjamin.delpy
2. **Rubeus** - GhostPack
3. **Certipy** - ly4k
4. **Impacket** - SecureAuthCorp
5. **Responder** - lgandx
6. **Coercer** - p0dalirius
7. **PetitPotam** - topotam
8. **hashcat** - hashcat.net
9. **CrackMapExec** - byt3bl33d3r / mpgn
10. **ADCS ESC Tools** - PKINITtools, Certify, ForgeCert

---

> **Lab Version:** 2.0-SNAPSHOT
> **Last Updated:** 2025-05-18
> **Next Review:** Monthly CVE update cycle
> **Status:** Build-ready
