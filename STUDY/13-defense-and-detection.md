# 13 — Defense and Detection

This chapter inverts the rest of the book. For each attack class, we ask:

1. **Why does this vulnerability exist?** (Design history, backward compat, default config.)
2. **What's the proper remediation?**
3. **How would a defender detect this in flight?** (Event IDs, Sysmon rules, Sigma signatures, KQL queries.)

You can't fully appreciate an attack until you've thought about how someone would catch it. And the inverse: you can't build durable defenses if you don't understand what an attacker is actually trying to do at the protocol level.

A red-team operator who can write Sigma rules for their own techniques becomes a better operator. A blue-team analyst who has executed Mimikatz once becomes a better analyst. This chapter is the meeting point.

---

## 13.0 (Concept) The two perspectives

Throughout chapters 1–12 you read every protocol "from the attacker's chair" — what fields you control, what the wire looks like, how to forge or replay. This chapter is "from the defender's chair":

- Where does the evidence land? (Which log, which host, which channel.)
- What's the false-positive rate of the detection?
- What does *not* leave a trace, and how do you compensate?
- What hardening would have prevented the attack altogether?

There's a third perspective worth holding alongside: **the IT operator who has to keep things running**. Many of the "right" hardening steps (disable NTLM, enforce LDAP signing, rotate krbtgt, require manager approval on cert templates) break legitimate things, generate help-desk tickets, and get rolled back. This chapter notes that operational cost where it bites hardest.

---

## 13.1 (Concept) The defender's data sources

```
+-----------------------------------------------------+
| Security event log (4xxx, 5xxx, 7xxx)              |  <- on every Windows host
+-----------------------------------------------------+
| Sysmon (1..29)                                      |  <- if installed
+-----------------------------------------------------+
| Windows Defender / MDE telemetry                    |  <- if installed
+-----------------------------------------------------+
| DC: directory service event log                     |  <- replication, DRSR, account changes
+-----------------------------------------------------+
| Network: PCAP / NetFlow / Zeek                      |  <- protocol-level signal
+-----------------------------------------------------+
| ADCS event log (Microsoft-Windows-CertificationAuthority/Operational) |
+-----------------------------------------------------+
| AD Audit (4662 with object DN, 5136 directory change) |
+-----------------------------------------------------+
| Defender for Identity (DfI) sensors on every DC     |
+-----------------------------------------------------+
| WMI-Activity Operational (WMI subscriptions)        |
+-----------------------------------------------------+
| PowerShell Operational (4103, 4104)                 |  <- script-block + module logging
+-----------------------------------------------------+
| SCM (Service Control Manager) log                   |  <- 7045 service install
+-----------------------------------------------------+
```

Most blue teams centralise in a SIEM (Splunk, Sentinel, ELK). The detections below are written as conceptual queries; translate to your SIEM language.

### Coverage gaps

Detection coverage usually falls into these buckets, in order of how often they're missing:

1. **No Sysmon** — most orgs run only the default Windows audit policy, which is anemic. Sysmon adds process tree, network connect, file integrity, and LSASS access events that the built-in log doesn't capture.
2. **No PowerShell logging** — turning on script-block logging (event 4104) is one line of policy but most orgs never do it.
3. **DC audit incomplete** — `Audit Directory Service Changes` is not enabled by default. Without it you don't get 5136 on object modifies.
4. **No DfI** — paid Microsoft product; small orgs skip it. Without DfI, DCSync/DCShadow/Golden are very hard to catch.
5. **No CA audit** — the ADCS operational log isn't centrally collected even by orgs that collect everything else.
6. **No SYSVOL FIM** — GPO and script implants land here; few orgs hash and diff SYSVOL.

Most of this chapter assumes a *competent* SIEM with Sysmon, PowerShell logging, full DC audit, and DfI — i.e., the upper-middle deployment, not the median.

---

## 13.2 Why intentionally vulnerable defaults persist

Active Directory turns 26 next year. Most of the protocols on the wire (Kerberos, NTLM, LDAP, MS-RPC, MS-DRSR) were designed for closed corporate networks in the late 1990s. Defaults assume a trusted LAN. Examples:

- **NTLM exists** because Kerberos rollouts had to coexist with NT4 (1996) for a decade.
- **LLMNR / NBT-NS exists** because NetBIOS name resolution predates DNS being universal on Windows.
- **Unconstrained delegation exists** because S4U wasn't introduced until Server 2003.
- **Pre-auth opt-out (`DONT_REQ_PREAUTH`)** is needed for some MIT-Kerberos interop scenarios.
- **MachineAccountQuota=10** lets users self-service domain-join their workstations.
- **DCSync ACEs on `Domain Controllers` group** because replication needs them.
- **EFSRPC enabled on DCs** because EFS used it for raw-file backup.
- **Spooler enabled on DCs** because print queues used to live everywhere.

Every one of these is a vulnerability *only* because the network it sits on is now hostile. Microsoft can't ship "default secure" without breaking existing customers — so defenders inherit the gap.

### The defender's bargain

Each hardening below has a *backwards-compat cost*. The blue team's job isn't just to apply them; it's to *measure* what breaks and decide whether the protection is worth it. Examples:

| Hardening | What breaks |
|---|---|
| Disable NTLM | Legacy apps (older SQL clients, scanners, MFPs) |
| Require SMB signing | 1% perf hit; some old SAN appliances |
| Require LDAP signing | Older Java/PHP LDAP clients |
| Disable Spooler everywhere | Print servers + DCs that double as print |
| Disable WebClient | WebDAV-mounted intranets, some intranet auth flows |
| MAQ=0 | Self-service join breaks; help desk handles all joins |
| LSA Protection (PPL) | Some EDR + antivirus that hook lsass break |
| Credential Guard | Hypervisor required; some older drivers won't load |
| StrongCertBindingEnforcement=2 | Old auth methods that mapped certs by anything but issuer+serial break |

The point isn't "do them all" — it's "know exactly what breaks before you flip the switch."

---

## 13.3 Detection: roasting

### Kerberoasting (CRED-001)

Wire signal: TGS-REQ for a user-account SPN with **RC4** etype where the user usually requests AES.

```
EventID 4769
  ServiceName: svc_jarvis
  TicketEncryptionType: 0x17   (RC4-HMAC, hex 23 decimal)
  Account: peter.parker
```

Sigma rule (paraphrased):

```yaml
title: Kerberoasting via RC4 TGS-REQ
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_krbtgt:
    ServiceName: 'krbtgt'           # not roastable; exclude
  filter_machine:
    ServiceName|endswith: '$'        # machine accounts; lower interest
  condition: selection and not filter_krbtgt
fields:
  - Account
  - ServiceName
  - IpAddress
```

False positives:
- Legitimate apps that only support RC4. (Old SQL clients, some scanners.)
- Misconfigured service accounts with RC4-only msDS-SupportedEncryptionTypes.

Best mitigation strategies:
- **Honeypot SPNs** — a fake SPN nobody but attackers would request is the cleanest detection (zero FP).
- Force AES on every service account: `Set-ADUser svc -KerberosEncryptionType AES128,AES256`.
- Group MSAs / gMSAs use 240-byte rotated passwords; if your service supports it, migrate.

#### KQL

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName != "krbtgt"
| where ServiceName !endswith "$"
| summarize count() by Account, ServiceName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 1
```

#### Why force AES isn't a complete fix

If the SPN owner *has* an AES key (i.e., the account's `msDS-SupportedEncryptionTypes` has AES bits set), an attacker can still request RC4 if the *user's own* account supports RC4 too. The clean fix: set `msDS-SupportedEncryptionTypes` on every account to AES-only AND set the domain-wide policy `Network security: Configure encryption types allowed for Kerberos` to exclude RC4.

### AS-REP roasting (CRED-002)

Signal: 4768 (TGT request) **without pre-authentication required** combined with `DONT_REQ_PREAUTH` flag on the target account.

```
EventID 4768
  PreAuthType: 0    # 0 = no preauth
  Status: 0x0       # success
  Account: tony.stark
```

Also: any account with `DONT_REQ_PREAUTH` UAC bit (4194304) is suspicious. Inventory regularly:

```powershell
PS> Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol
```

Mitigation:
- Strip the `DONT_REQ_PREAUTH` bit from every account that has it.
- For accounts that genuinely need it (rare MIT-Kerberos interop), monitor 4768 with PreAuthType=0 for those specific accounts only.

---

## 13.4 Detection: DCSync

### Why DCSync is hard to detect at the ACL level

DCs themselves replicate via DRSR constantly. The signal is: **DRSR from a non-DC client**.

```
EventID 4662
  ObjectName: <Domain Naming Context root>
  Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}     # DS-Replication-Get-Changes
              {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}     # DS-Replication-Get-Changes-All
              {89e95b76-444d-4c62-991a-0facbeda640c}     # DS-Replication-Get-Changes-In-Filtered-Set
  Accessing: peter.parker (NOT a DC computer account)
```

```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa" or Properties has "1131f6ad" or Properties has "89e95b76"
| where SubjectUserName !endswith "$"    // exclude machine accounts
| where SubjectUserName !in ("krbtgt", "DC1$", "DC2$")
| project TimeGenerated, SubjectUserName, ObjectName, Properties, IpAddress
```

Defender for Identity flags this natively as "Suspected DCSync."

### Why machine-account exclusion can backfire

If an attacker DCSyncs from a *legitimate-looking* computer account (e.g., they compromised `dc01$` itself, or a server they've made a computer trust on), the `!endswith '$'` exclusion swallows it. Tighten by enumerating the *actual* DC machine accounts (members of the `Domain Controllers` group) and whitelisting only those:

```kql
let DCMachines = SecurityEvent
    | where EventID == 4769 and ServiceName == "krbtgt"
    | summarize by Account 
    | where Account endswith "$";
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa"
| where SubjectUserName !in (DCMachines)
```

### Mitigation

Remove unneeded ACEs. Only the `Domain Controllers` group should have DS-Replication-Get-Changes/-All. Audit `nTSecurityDescriptor` of the domain root for any extra principals:

```powershell
PS> $sd = (Get-ADObject 'DC=corp,DC=local' -Properties nTSecurityDescriptor).nTSecurityDescriptor
PS> $sd.Access | ? { $_.ObjectType -in @('1131f6aa-...','1131f6ad-...') }
```

Anyone not in `Domain Controllers` / `Enterprise Domain Controllers` is suspect.

---

## 13.5 Detection: NTLM relay + coercion

### Coercion signal

PetitPotam triggers `EfsRpcOpenFileRaw` from a DC against an attacker IP.

```
EventID 5145 (detailed file share access)   on the attacker side: usually not logged.

On DC: no direct log for outbound EFSRPC.
Network signal: SMB → \PIPE\efsrpc from DC to non-domain host.
```

Best detection is at the network layer. Sysmon EID 3 (network connect) on DC for an SMB connection going to a non-DC, non-corporate IP is high-fidelity.

```yaml
title: Outbound SMB from DC to non-DC host
detection:
  selection:
    EventID: 3
    Image|endswith: '\System'      # DC outbound
    DestinationPort: 445
  filter:
    DestinationIp: '10.10.0.0/24'  # exclude corp subnet
    DestinationIp: '10.30.0.0/24'  # exclude root.corp DCs
  condition: selection and not filter
```

### Relay signal

`ntlmrelayx` forwards. On the target, the inbound auth has:

```
EventID 4624
  LogonType: 3 (Network)
  AuthenticationPackage: NTLM
  Workstation Name: WORKGROUP or weird
  Source Network Address: <attacker IP>    # NOT the victim's IP
```

The mismatch between the source IP (attacker) and the authenticating identity (victim machine account) is the giveaway.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName endswith "$"          // machine acct auth
| extend account_host = trim_end("$", TargetUserName)
| extend account_ip = lookup_dns(account_host)
| where IpAddress != account_ip              // mismatch
```

(The `lookup_dns` is pseudocode — you'd join against your CMDB or DNS log.)

### Mitigation hierarchy

1. **Disable NTLM** entirely. Hardest, breaks legacy apps.
2. **Require SMB signing everywhere.** GPO: `Microsoft network server: Digitally sign communications (always) = Enabled`.
3. **Require LDAP signing + channel binding.** Server 2022+ enforces by default; legacy DCs need explicit setting.
4. **Disable WebClient service on hosts.** Removes HTTP coercion sink that enables WebDAV → HTTP relay.
5. **Disable Spooler on DCs.** Removes one coercion vector (SpoolSample).
6. **Patch EFSRPC** (KB5005413) and disable the EFSRPC RPC pipe on DCs.
7. **EPA (Extended Protection for Authentication)** on HTTP services that consume NTLM — binds NTLM to the TLS channel so relays from non-TLS can't succeed.

### Coercion-family complete table

| Family | Trigger pipe | Patch state | Disable |
|---|---|---|---|
| PetitPotam (MS-EFSR) | `\PIPE\efsrpc`, `\PIPE\lsarpc` | KB5005413 partial | Disable EFSRPC interface (KB) |
| SpoolSample (MS-RPRN) | `\PIPE\spoolss` | Not directly patchable | Disable Spooler service |
| DFSCoerce (MS-DFSNM) | `\PIPE\netdfs` | KB5025885 partial | Disable DFS Namespace service if unused |
| ShadowCoerce (MS-FSRVP) | `\PIPE\FssagentRpc` | KB5012170 | Disable File Server VSS Agent Service |
| PrinterBug variants | `\PIPE\spoolss` | n/a | Spooler service |

---

## 13.6 Detection: ADCS abuse

ADCS event log on CA (`Microsoft-Windows-CertificationAuthority/Operational`):

```
EventID 4886: Certificate Services received certificate request
EventID 4887: Certificate Services approved request and issued certificate
  RequestId
  RequesterName: corp\peter.parker
  SubjectAltName: Administrator@corp.local   <-- ESC1 signal!
  Template: VulnerableTemplate
```

Sigma idea: any 4887 where `Requester ≠ SAN principal` should fire.

```kql
ADCSEvent
| where EventID == 4887
| extend SAN_user = extract(@"upn=([^,]+)", 1, SubjectAltName)
| where isnotempty(SAN_user)
| where !contains(RequesterName, split(SAN_user, "@")[0])
```

### Per-ESC detection table

| ESC | Best detection | Best prevention |
|---|---|---|
| ESC1 | 4887 with SAN ≠ requester | Remove `ENROLLEE_SUPPLIES_SUBJECT` flag; require manager approval |
| ESC2 | 4887 with "Any Purpose" EKU | Strip "Any Purpose" EKU; restrict enroll |
| ESC3 | 4887 with Certificate Request Agent EKU | Restrict enrollment-agent EKU; restrict enrollee |
| ESC4 | 5136 on cert template DACL | Audit template DACLs; remove low-priv write |
| ESC5 | 5136 on CA / `pKIEnrollmentService` ACL | Audit CA object ACLs |
| ESC6 | Registry change to CA `EditFlags` | Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` |
| ESC7 | Audit CA `Officer` / `Manage CA` permission changes | Reset CA permissions |
| ESC8 | 4886 from non-CA-management IP | Disable HTTP enrollment endpoint; enforce HTTPS + EPA |
| ESC9 | Cert request without `szOID_NTDS_CA_SECURITY_EXT` for a sensitive UPN | `StrongCertificateBindingEnforcement=2`; set CertificateMappingMethods |
| ESC10 | 4767 (password reset) followed by PKINIT for the reset user | StrongCertBinding=2 |
| ESC11 | RPC enrollment over unauthenticated channel | Require channel binding on LDAP and IPSec on RPC enrollment |
| ESC13 | Cert with issuance policy OID mapped to high-priv group | Audit issuance-policy → group mappings |
| ESC14 | 5136 on `altSecurityIdentities` of protected user | Audit `altSecurityIdentities` writes |
| ESC15 | Cert request with unexpected OID extensions | Patch CVE-2024-49019 (May 2024 cumulative) |
| ESC16 | Change to CA `disabledExtensionList` registry | Patch + audit `disabledExtensionList` on CA |
| Certifried | Machine account password reset → PKINIT for that machine | Patch May 2022 (KB5014754); enforce strong cert binding |

### Mitigation summary commands

```powershell
# Force manager approval on a template:
$t = Get-ADObject "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
Set-ADObject $t -Replace @{
    'msPKI-Enrollment-Flag' = 0x02   # CT_FLAG_PEND_ALL_REQUESTS
    'msPKI-Certificate-Name-Flag' = 0x0   # remove ENROLLEE_SUPPLIES_SUBJECT
}

# Disable EDITF_ATTRIBUTESUBJECTALTNAME2:
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc; net start certsvc

# Enforce strong cert binding (KB5014754):
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
```

---

## 13.7 Detection: Golden/Silver/Diamond/Sapphire tickets

### Golden

Wire signal: TGS-REQ with a TGT that *was never issued* (no preceding AS-REQ).

```
EventID 4769 without a corresponding 4768 in the lookback window for the same client.
TicketEncryptionType: 0x17 (Mimikatz default — old) or 0x12 (AES256)
Lifetime: 10 years (Mimikatz default) — pathological
ClientName: <does not exist in AD or is disabled>
```

Detection logic (correlation):

```kql
let tgs = SecurityEvent
    | where EventID == 4769 and TicketEncryptionType == "0x17"
    | project TimeGenerated, Account, ServiceName, IpAddress;
let tgt = SecurityEvent
    | where EventID == 4768
    | project tgt_time = TimeGenerated, Account;
tgs
| join kind=leftouter tgt on Account
| where isempty(tgt_time) or tgs.TimeGenerated > tgt_time + 10h
```

Defender for Identity → "Suspected Golden Ticket usage."

#### Honeypot-account approach

Create a disabled user that nobody should ever request a TGS for. Any 4769 with this account in ClientName = Golden Ticket usage.

```
PS> New-ADUser -Name 'svc_backup_legacy' -Enabled $false
PS> # Forge a Golden citing svc_backup_legacy → 4769 with that name → high-fidelity alert
```

### Silver

No 4769 — the attacker forges the TGS directly. So **absence** of a 4769 paired with a service authentication is the signal.

Hard to detect with event logs alone. Network: Kerberos AP-REQ without preceding TGS-REQ for that SPN/client tuple within the ticket lifetime.

The KB5020805 PAC validation update adds extra signatures to the PAC. A Silver ticket forged without knowledge of the krbtgt key will fail validation when the service forwards the PAC to the DC for verification. *Enable PAC validation* in service configs where possible.

### Diamond / Sapphire

These have the corresponding AS-REQ + TGS-REQ. The signal is **PAC anomaly**: PAC group membership claims that the user shouldn't have, or PAC signatures that don't match the on-disk krbtgt key.

Microsoft introduced **PAC validation** improvements (KB5008380 → KB5020805) — DCs now embed extra PAC fields (`PAC_REQUESTOR`, `PAC_ATTRIBUTES_INFO`) and validate them on receipt of AP-REQ. Patch + enforce.

Defender for Identity also looks at:
- PAC user not in expected groups (LDAP cross-check).
- AS-REQ timestamps vs decoded TGT enc-part timestamps don't match.

### Detection summary

| Forge | Has 4768? | Has 4769? | Distinguishing field |
|---|---|---|---|
| Golden | No | Yes (service requests) | Missing 4768; weird PAC; long lifetime |
| Silver | No | No | AP-REQ to service with no DC trace |
| Diamond | Yes | Yes | PAC group claims don't match user's real groups |
| Sapphire | Yes (S4U2Self) | Yes | S4U2Self from non-DC host; resigned TGT |

---

## 13.8 Detection: lateral movement

### psexec.py

```
EventID 7045 (service install)  on target
  ServiceName: RemComSvc / random
  ServiceFileName: \\.\PIPE\<random> or %SystemRoot%\<random>.exe
  ServiceType: kernel mode driver  OR  user mode service
  StartType: demand start
```

EID 7045 from an unexpected user, with a temp-looking service name, is a high-confidence psexec signal.

```kql
Event
| where EventID == 7045
| where ServiceName matches regex @"^[a-zA-Z]{8,16}$"   // random-looking
   or ImagePath contains "\\.\PIPE\\"
   or ImagePath contains "%SystemRoot%\\" and ImagePath matches regex @".*[a-f0-9]{6,}\.exe"
```

### wmiexec.py

```
EventID 4688 (process create)
  Parent: wmiprvse.exe                   # WMI provider host
  Command line: cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<timestamp>
  TokenElevation: TokenElevationTypeFull
```

The `1> \\127.0.0.1\ADMIN$\__` is the wmiexec output-redirection signature. Highest-confidence wmiexec detection.

```yaml
title: wmiexec output-redirection pattern
detection:
  selection:
    EventID: 4688
    ParentImage|endswith: '\wmiprvse.exe'
    CommandLine|contains: '\\127.0.0.1\ADMIN$\__'
  condition: selection
```

### atexec.py / Scheduled Task remote

```
EventID 4698 (scheduled task created)
  TaskName: random (e.g., \kxYqz)
  Author: random
  RunAs: SYSTEM
  Trigger: At <time>
  Action: cmd.exe /C <command> > \\127.0.0.1\ADMIN$\__<random>
```

### smbexec.py

```
EventID 7045
  ServiceName: BTOBTO (impacket default) or random
  ImagePath: %COMSPEC% /Q /c echo ... > \\127.0.0.1\<share>\__output
```

### dcomexec.py

```
EventID 4688
  Parent: mmc.exe (when using MMC20.Application CLSID)
       OR explorer.exe (Excel.Application / ShellWindows CLSIDs)
  CommandLine: cmd /c ...
```

### evil-winrm

```
EventID 4624
  LogonType: 3
  AuthenticationPackage: NTLM or Kerberos

EventID 4688
  Parent: wsmprovhost.exe
  Command line: -EncodedCommand ...
```

`wsmprovhost.exe` is the WinRM child — anything spawning from it is remote PowerShell. Pair with PowerShell ScriptBlock logging (4104) for content visibility.

```kql
Event
| where EventID == 4688
| extend parent = tostring(EventData.ParentImage)
| where parent endswith "wsmprovhost.exe"
| project TimeGenerated, Computer, CommandLine, SubjectUserName
```

### Cross-tool detection summary

| Tool | Service install (7045) | New task (4698) | wmiprvse child (4688) | wsmprovhost child (4688) |
|---|---|---|---|---|
| psexec.py | YES | no | no | no |
| smbexec.py | YES | no | no | no |
| wmiexec.py | no | no | **YES** | no |
| atexec.py | no | **YES** | no | no |
| dcomexec.py | no | no | partial (mmc.exe parent) | no |
| evil-winrm | no | no | no | **YES** |
| sc.exe + start | YES | no | no | no |
| PsExec (Sysinternals) | YES (service "PSEXESVC") | no | no | no |

---

## 13.9 Detection: LSASS access

```
EventID 4656 / 4663
  ObjectName: \Device\HarddiskVolume?\Windows\System32\lsass.exe
  AccessMask: 0x10 (VM_READ) or 0x1010 (VM_READ + VM_OPERATION)
  ProcessName: <not a known LSASS-talker — i.e., NOT csrss.exe, services.exe, wininit.exe>

Sysmon EID 10 (ProcessAccess)
  TargetImage: lsass.exe
  GrantedAccess: 0x1010 / 0x1410 / 0x1438
  SourceImage: cmd.exe / powershell.exe / rundll32.exe / taskmgr.exe
```

The full access-mask cheat sheet for "they're dumping LSASS":

| Mask | Rights | Tools |
|---|---|---|
| 0x10 | PROCESS_VM_READ | basic dump |
| 0x1010 | VM_READ + VM_OPERATION | comsvcs MiniDump, procdump |
| 0x1410 | VM_READ + VM_OPERATION + DUP_HANDLE | mimikatz minidump |
| 0x143A | full LSASS open | mimikatz default |

```yaml
title: Suspicious LSASS access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: '0x1410'
  filter:
    SourceImage|endswith:
      - '\csrss.exe'
      - '\services.exe'
      - '\wininit.exe'
      - '\msmpeng.exe'      # Defender
  condition: selection and not filter
```

### Mitigation

- **Credential Guard** — moves LSASS secrets into a VBS-isolated process; reading lsass.exe yields encrypted garbage.
- **LSA Protection** (`RunAsPPL=1`) — only signed/protected processes can open lsass for read.
- **Defender ASR rule** "Block credential stealing from LSASS" — kills mimikatz-pattern access.

```reg
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    RunAsPPL = 1   (DWORD)
```

Plus the Hyper-V Code Integrity (HVCI) requirement for Credential Guard.

### Bypass-style attacks to be aware of

Defenders should know that even with LSA Protection, an attacker who has SYSTEM and can load a kernel driver (signed) can bypass PPL. The bypasses (mimikatz `!processprotect`, PPLKiller, PPLdump, EDRSandblast) require a vulnerable signed driver. Watch for unsigned-driver-load attempts and for known vulnerable drivers (e.g., `rwdrv.sys`, `gdrv.sys`).

---

## 13.10 Detection: DCShadow

ADTS replication metadata changes are recorded:

```
EventID 4742 (computer account changed)
  Target: a 'DC' that isn't really a DC (no nTDSDSA child object normally)
  SPN changes: GC/... or E3514235-4B06-11D1-AB04-00C04FC2DCD2/...
```

Defender for Identity flags "Suspected DCShadow" by correlating the SPN registration + DRSR push.

Detect at AD level by enumerating Configuration NC's `CN=Servers` periodically and alerting on any new server object that doesn't have a matching nTDSDSA + computer account in `Domain Controllers` group.

```powershell
PS> Get-ADObject -SearchBase 'CN=Sites,CN=Configuration,DC=corp,DC=local' -Filter 'objectClass -eq "server"' \
    | ForEach-Object {
        $dsa = Get-ADObject -Filter "name -eq 'NTDS Settings'" -SearchBase $_.DistinguishedName
        if (-not $dsa) { Write-Warning "Phantom server: $($_.Name)" }
    }
```

### Why this is fragile

DCShadow self-cleans — after the push, mimikatz removes the fake nTDSDSA + SPN entries. Detection must run **during** the attack window (a few seconds) or rely on the ETW/DfI signal.

---

## 13.11 Detection: AdminSDHolder backdoor

```
EventID 5136 (directory service object modified)
  ObjectDN: CN=AdminSDHolder,CN=System,DC=corp,DC=local
  AttributeLDAPDisplayName: nTSecurityDescriptor
  OperationType: Value Added
```

Any 5136 on AdminSDHolder is high-fidelity. Baseline + alert.

```kql
SecurityEvent
| where EventID == 5136
| where ObjectDN contains "CN=AdminSDHolder"
| where AttributeLDAPDisplayName == "nTSecurityDescriptor"
```

Also alert on 4780 (Account Operators-protected DACL reset) which is the SDProp running — review ACEs after the run.

### Baselining recipe

Capture a known-good AdminSDHolder ACL once:

```powershell
PS> (Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local').Access | \
        Export-Csv adminsdholder-baseline.csv
```

Run a daily compare-Object task; alert on any drift.

---

## 13.12 Detection: ZeroLogon

```
EventID 4742 (computer account changed)
  Target: DC$ (e.g., DC01$)
  PasswordLastSet: just now (anomalous — DC machine passwords rotate ~monthly)
  AuthenticationPackage: NETLOGON
  SourceWorkstation: <attacker> or blank
```

Microsoft patched in August 2020 (KB4565351), enforced in February 2021 — the patch enforces NRPC signing/sealing. The DVAD lab sets `FullSecureChannelProtection=0` to leave it exploitable.

### Detection logic

```kql
SecurityEvent
| where EventID == 4742
| where TargetUserName endswith "$"          // computer account
| where TargetUserName in (DCList)            // it's a DC
| extend pwdage = now() - todatetime(PasswordLastSet)
| where pwdage < 1h
| where SubjectUserName != "SYSTEM"           // not normal rotation
```

### Mitigation

- Apply the patch (it's mandatory since 2021).
- Set `FullSecureChannelProtection=1`.
- Monitor 4742 with DC targets.

---

## 13.13 Detection: noPac (sAMAccountName spoofing)

CVE-2021-42278 + CVE-2021-42287. Attacker creates a computer account with sAMAccountName matching a DC's name minus the `$`, requests a TGT for it, then requests a TGS via S4U2Self.

```
Events on DC:
4741 (computer account created) for "DC1" (no $)
4781 (account rename)            DC1 → something else
4624 from a TGT requested with a sAMAccountName that previously resolved to a DC
```

Sigma:

```yaml
title: noPac sAMAccountName spoof
detection:
  rename:
    EventID: 4781
    OldTargetUserName|endswith: '$'           # was DC$ at creation
    NewTargetUserName|contains: 'DC'           # renamed to mimic DC
  newcomp:
    EventID: 4741
    TargetUserName|endswith: '$'
    SAMAccountName|in: ['DC1', 'DC2']         # without $
  condition: newcomp or rename
```

### Mitigation

Patch (KB5008380 + KB5020805). The patch adds a `PAC_ATTRIBUTES_INFO` signature that allows the DC to detect when the TGT references a renamed account.

---

## 13.14 Detection: shadow credentials (msDS-KeyCredentialLink)

Plant signal:

```
EventID 5136
  ObjectDN: CN=<target>,CN=Users,DC=corp,DC=local
  AttributeLDAPDisplayName: msDS-KeyCredentialLink
  OperationType: Value Added
```

Use signal: PKINIT auth (4768 with PreAuthType=15 — PKINIT) for an account that wouldn't normally use cert auth.

### Detection

```kql
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| where ObjectDN contains "CN=Users"
| where SubjectUserName != "DC01$"   // legit Windows Hello provisioning
```

### Mitigation

Audit `msDS-KeyCredentialLink` weekly on every privileged account. Defender for Identity has a built-in detection.

---

## 13.15 Detection: RBCD

Plant signal:

```
EventID 5136
  ObjectDN: CN=DC01,OU=Domain Controllers,DC=corp,DC=local
  AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity
  OperationType: Value Added
```

Use signal: S4U2Self followed by S4U2Proxy from an unusual host.

```kql
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "msDS-AllowedToActOnBehalfOfOtherIdentity"
```

### Mitigation

- **MAQ=0** — prevents low-priv users from creating the attacker-controlled computer needed for the chain.
- Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` on every high-value computer; baseline.
- LDAP signing + channel binding — closes the relay path that often sets RBCD.

---

## 13.16 Detection: GPO implants

Plant signal:

```
EventID 5136
  ObjectDN: CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=local
  AttributeLDAPDisplayName: gPCFileSysPath / versionNumber
```

SYSVOL file write signal — every GPO edit writes to the GPT path:

```
EventID 4663 (object access)
  ObjectName: \\corp.local\SYSVOL\corp.local\Policies\{...}\...
  ObjectType: File
  AccessMask: 0x6 / 0x2 (WriteData)
```

### Mitigation + detection

- File integrity monitoring (FIM) on SYSVOL with hash baseline.
- Audit `versionNumber` on every GPO; bump → flag.
- Review SharpGPOAbuse signature files (`ScheduledTasks.xml`, `scripts.ini`) for changes.

---

## 13.17 Detection: PrintNightmare

Server-side variant (CVE-2021-1675 / 34527):

```
EventID 4673 (PrintConfig access)
  PrivilegeList: SeLoadDriverPrivilege
  ProcessName: spoolsv.exe
```

Driver-load event:

```
EventID 808 (Microsoft-Windows-PrintService/Operational)
  "The print spooler failed to load a plug-in module"
  Path: <attacker-supplied DLL>
```

### Mitigation

- **Disable Spooler on DCs** — `Stop-Service Spooler -Force; Set-Service -StartupType Disabled`.
- Disable PrintNightmare via registry on hosts that need printing but not driver-install from clients:

```reg
HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators = 1   (DWORD)
```

---

## 13.18 Detection: Skeleton Key

The patch is in-memory; no event log entry for the patch itself. Signals:

- 4769 with **etype downgrades** (suddenly RC4 for an account that always uses AES) — could be skeleton.
- 4768 where the user supplied a known-bad password but the auth succeeded — only catchable if you have honeypot accounts.

LSA Protection (`RunAsPPL=1`) blocks the patch attempt entirely. Microsoft's `Set-ProcessMitigation` and Credential Guard close other avenues.

---

## 13.19 Detection: krbtgt rotation indicators (defender's side)

Defenders rotating krbtgt should look for:

```
EventID 4781 (account renamed)
EventID 4624 (logon) krbtgt — rare; should investigate
EventID 4738 (user account changed) on krbtgt — rotation
```

The official Microsoft script logs to a known location. If you see krbtgt changes outside the rotation script's audit trail, treat as attacker activity.

---

## 13.20 Honey tokens

Concept: plant artefacts an attacker will use, but a legitimate user never would.

| Honey | What | Trip signal |
|---|---|---|
| Honey SPN | Create a fake user `svc_honey$kerberoast` with SPN; password is random | 4769 for that SPN with RC4 |
| Honey ADCS template | Vulnerable-looking template (`ENROLLEE_SUPPLIES_SUBJECT` set, "Any Purpose" EKU), no enroll permissions to anyone | 4886 with that template name |
| Honey share | `\\fileserver\Backups\Passwords.kdbx` — empty | 5145 audit on that file path |
| Honey LAPS | LAPS attribute readable by a fake group; populate fake password | 4662 on the attribute |
| Honey DPAPI | A fake LSA secret blob in the registry | reg-read alerts |
| Honey computer | Phantom hostname in DNS pointing to a trap host | DNS query for that name |
| Honey GPP password | A `Groups.xml` in SYSVOL with a `cpassword` decoding to a random value (no real account) | login attempt with that value |
| Honey AdminSDHolder ACE | Add a known-fake user as GenericAll on AdminSDHolder; alert on its use | 4624 / 4768 for the fake user |
| Honey cert | Issue a cert for a fake admin; alert on its use | 4768 PKINIT for that user |
| Honey gMSA | A gMSA whose msDS-ManagedPasswordId is read by an unexpected principal | 4662 |

The advantage: **no false positives**. The disadvantage: you only catch attackers who *look*, not attackers who *know* the environment (insider).

### Designing a honey SPN

```powershell
PS> New-ADUser -Name 'svc_legacy_sql' -UserPrincipalName 'svc_legacy_sql@corp.local' \
       -AccountPassword (New-Password 32) -ServicePrincipalNames 'MSSQLSvc/legacy.corp.local:1433' \
       -Enabled $false
# Force RC4-only so the TGS-REQ comes back RC4 (defenders' detection):
Set-ADUser svc_legacy_sql -KerberosEncryptionType 4  # RC4 only
```

The account is disabled — nothing real authenticates as it. Any 4769 for `MSSQLSvc/legacy.corp.local:1433` is an attacker.

---

## 13.21 The defender's playbook

Order of priority for DVAD-style environments:

1. **Patch everything.** ZeroLogon, PrintNightmare, noPac, Certifried, ESC15/16 all have patches. The cheapest big wins.
2. **Disable LLMNR / NBT-NS / mDNS.** GPO.
3. **Disable IPv6 if not used.** Removes mitm6 vector.
4. **Disable WebClient on user endpoints.** Removes HTTP-coercion sink.
5. **Disable Spooler on DCs and any non-print servers.**
6. **Enable SMB signing required + LDAP signing/channel binding.**
7. **Rotate krbtgt twice annually, plus after any DA compromise.**
8. **Set `MachineAccountQuota=0`.** Stops the RBCD chain dead.
9. **Audit and minimise:** AdminSDHolder ACEs, DCSync ACEs, GenericWrite on Tier-0 objects, msDS-KeyCredentialLink on privileged users, msDS-AllowedToActOnBehalfOfOtherIdentity on any high-value computer.
10. **ADCS hardening:** enable strong cert binding (mode 2), turn off web enrollment if unused, fix all template ACLs, disable `EDITF_ATTRIBUTESUBJECTALTNAME2`.
11. **LSA Protection (PPL) + Credential Guard.**
12. **EDR.** Defender for Endpoint or equivalent. Without it, most LSASS/Kerberos detections are theory.
13. **Tiered admin model.** Tier-0 (DCs, ADCS, AzureAD Connect) accounts never log in to Tier-1/2 hosts. Eliminates LSASS exposure.
14. **Disable NTLM** by phase (audit first, then deny domain-wide).
15. **Defender for Identity** on every DC. Catches DCSync/DCShadow/Golden.
16. **PAW (Privileged Access Workstation)** for every Tier-0 admin.
17. **JIT/JEA** — Just-In-Time admin elevation via Microsoft PAM (LAPS for users).
18. **Forest hardening:** enable SID filtering on every external trust; remove forest trusts that aren't load-bearing.

The order matters: items 1–6 close the **initial access** doors, 7–10 close the **escalation paths**, 11–13 raise the bar for **persistence techniques** in Chapter 12, and 14–18 are the structural changes that pay off over years.

### Cost-vs-value matrix

| Hardening | Defensive value (1-5) | Operational cost (1-5) | Order |
|---|---|---|---|
| Patch | 5 | 2 | 1 |
| Disable LLMNR | 4 | 1 | 2 |
| MAQ=0 | 4 | 2 (help-desk joins) | 3 |
| krbtgt rotation | 3 | 2 (Kerberos errors for users) | 4 |
| SMB signing | 4 | 1 | 5 |
| LDAP signing | 4 | 2 (some old apps break) | 6 |
| Disable Spooler on DCs | 4 | 1 | 7 |
| Disable WebClient | 3 | 1 | 8 |
| LSA Protection | 4 | 2 (some EDR break) | 9 |
| Credential Guard | 4 | 3 (hypervisor required) | 10 |
| StrongCertBinding=2 | 5 | 3 (auth changes needed) | 11 |
| Tier model | 5 | 5 (cultural shift) | 12 |
| Disable NTLM | 5 | 5 (everything legacy breaks) | 13 |
| Defender for Identity | 4 | 2 (licensing cost) | 14 |

---

## 13.22 (Concept) Detection engineering as an iterative process

A first-pass detection (e.g., "any TGS-REQ with RC4") drowns the SOC in alerts. Iterate:

1. **Baseline** — run the query for 14 days, see what's normal.
2. **Filter** — exclude the noisy legitimate sources.
3. **Tune** — adjust thresholds.
4. **Validate** — execute the attack in a lab and confirm the rule fires.
5. **Document** — playbook for analyst on what to do when it fires.

A rule with a 90% false-positive rate gets disabled by the SOC within a week. Better to ship one tight rule that catches 30% of attacks than a sloppy rule that catches 90% but burns analyst trust.

### Quality tiers

| Tier | Definition | Example |
|---|---|---|
| A | No false positives ever | Honey-SPN 4769 |
| B | <1 FP/week, requires lookup | DCSync from non-DC |
| C | 1-10 FPs/week, requires correlation | RC4 TGS-REQ |
| D | High FP, exploratory | Any SMB to non-corp IP |

Aim to convert C-tier rules into B-tier via better filters, and B-tier into A-tier via honeypots.

---

## 13.23 (Concept) MITRE ATT&CK mapping

Every attack in this book maps to an ATT&CK technique. Knowing the mapping helps:

- Communicate with security leadership in their language.
- Cross-reference defender tooling that advertises ATT&CK coverage.
- Identify gaps in your detection (techniques with no rule).

| DVAD attack | ATT&CK |
|---|---|
| LLMNR poisoning | T1557.001 |
| Kerberoasting | T1558.003 |
| AS-REP roast | T1558.004 |
| DCSync | T1003.006 |
| LSASS dump | T1003.001 |
| Pass-the-hash | T1550.002 |
| Pass-the-ticket | T1550.003 |
| Overpass-the-hash | T1558.003 |
| Golden Ticket | T1558.001 |
| Silver Ticket | T1558.002 |
| Diamond Ticket | T1558.001 |
| Skeleton Key | T1556.001 |
| DCShadow | T1207 |
| AdminSDHolder | T1098 |
| GPO modification | T1484.001 |
| ESC1-16 | T1649 |
| SID History | T1134.005 |
| Trust ticket forge | T1558.001 |
| RBCD | T1134.005 |
| ZeroLogon | T1210 |
| PrintNightmare | T1068 |
| noPac | T1078.002 |

---

## Lab exercises

### Exercise 13.A — Map every attack you executed to a detection

For each flag you captured in the previous chapters, write the Sigma rule (in pseudo-form) that would have caught it. Compare against the patterns in this chapter. Where your rule would *not* fire, identify why and propose a fix.

### Exercise 13.B — Plant honeypots

In your DVAD instance:
1. Create user `svc_honey$kerberoast` with SPN `MSSQLSvc/honey.corp.local:1433` and 32-char random password, AccountDisabled, KerberosEncryptionType=RC4-only.
2. From `peter.parker`, run Kerberoast. The DC issues a TGS.
3. Confirm event 4769 with ServiceName=svc_honey$kerberoast and RC4 etype is logged on dc01.

(You'd then build a SIEM alert on exactly that combo.)

### Exercise 13.C — Hardening drill

Pick three attacks you used. For each, apply the fix from §13.21. Re-run the attack. Verify it now fails. Roll back so the lab works for the next attacker.

Suggested set:
- **SMB signing required** → break ntlmrelayx to SMB.
- **Disable WebClient** → break PrivExchange-style HTTP relay.
- **StrongCertificateBindingEnforcement=2** → break ESC9.

### Exercise 13.D — Build a Sigma → KQL conversion

Pick three Sigma rules from this chapter. Convert each to KQL (or your SIEM's language). Execute against the DVAD log set (you'll need to enable Sysmon and forward to a SIEM — or just run against `wevtutil qe` output).

### Exercise 13.E — Baseline AdminSDHolder

1. Capture AdminSDHolder's full ACL.
2. Run Exercise 12.D (plant ACE).
3. Run a diff. Confirm your alert would catch the change.
4. Remove the ACE. Confirm diff is clean again.

### Exercise 13.F — Detection-only mode

For one week of lab time, instead of running attacks, run *detections*. Build a SIEM rule for each of the 12 attack families covered. Run a known-good attack against each. Verify fire rate, calculate FP rate against your normal lab traffic.

### Exercise 13.G — Defender for Identity simulator

If you don't have a DfI license, build a lightweight Python script that watches `wevtutil` for the events in this chapter and prints alerts. It won't catch DCShadow (which needs network sensors) but will catch DCSync, Golden, RBCD plant, AdminSDHolder edit.

### Exercise 13.H — Tabletop: SOC playbook

Write a 1-page analyst playbook for "AdminSDHolder ACL changed" alert. Include: triage questions, containment steps, escalation path, evidence to preserve, communication template.

---

## Self-check questions

1. Why is "disable NTLM" rarely possible in practice?
2. What's the difference between LSA Protection and Credential Guard?
3. Why does a Silver ticket leave less trace than a Golden ticket?
4. What's the role of the 1131f6aa GUID in DCSync detection?
5. Why does setting `MachineAccountQuota=0` neutralise the RBCD chain even when GenericWrite remains?
6. How does Defender for Identity detect DCShadow without seeing the DRSR traffic on disk?
7. What's the difference between a honey SPN and a real low-priv service SPN, from the attacker's view?
8. Why is SYSVOL FIM a useful complement to LDAP audit for GPO-implant detection?
9. What's the operational cost of `StrongCertificateBindingEnforcement=2` for a legacy cert-auth deployment?
10. Why is `Audit Directory Service Changes` not on by default, and what's the perf impact of enabling it?
11. What signal differentiates psexec.py from wmiexec.py in event logs alone?
12. Why are events 4768/4769 by themselves insufficient to catch Diamond tickets?
13. What's the operational risk of disabling Spooler on DCs?
14. Why does Credential Guard not break PrintNightmare?
15. What detection do you have for "Skeleton Key has been deployed on a DC"?
16. Why is `MachineAccountQuota=10` the default, given the RBCD chain?
17. What's the difference between event 5136 and event 4662 for AD object changes?
18. Why does Defender ASR's "Block credential stealing from LSASS" miss nanodump?
19. What's the difference between disabling WebClient on a host vs `RequireSecuritySignature` on SMB?
20. Why does a forest trust with `QUARANTINED_DOMAIN=1` not stop a forged TGT signed by the trust key?

---

## References

- **Microsoft — *Securing Active Directory*** — official hardening guide.
- **MITRE ATT&CK** — every technique in this book maps to an ATT&CK ID.
- **Sigma rule repository** (github.com/SigmaHQ/sigma) — community-maintained detection signatures.
- **Roberto Rodriguez — Threat Hunter Playbook** — open detection content.
- **Microsoft — *PAC validation* KB5020805** — the patch that closes most ticket forgery loopholes.
- **Microsoft — *KB5005413: Mitigating NTLM Relay Attacks***.
- **Microsoft — *KB5014754: Certificate-based authentication changes***.
- **Specter Ops — *Certified Pre-Owned*** — ADCS attack reference and remediation table.
- **Florian Roth — Sigma Rule Authoring** — how to write good detection content.
- **Microsoft — *Defender for Identity detection list*** — the canonical "what DfI catches" reference.
- **PingCastle** — free AD assessment tool that scores most of the issues in this chapter.

Next: [14-capstone.md](14-capstone.md).
