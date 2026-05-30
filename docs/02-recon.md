# 02 — Reconnaissance (REC-001..015)

Recon is the first 30 minutes of any engagement. Goal: build a map of users, computers, groups, ACLs, trusts, SPNs, GPOs, DNS, shares, and ADCS templates — without anyone noticing. Everything here works **as any authenticated domain user** (often even unauthenticated) because DVAD doesn't filter LDAP reads, doesn't restrict null sessions hard, has zone transfers on, and broadcasts SQL Browser.

Run from your **Kali / BlackArch** on the host bridge (`10.10.0.1` from inside the lab) — reachable to `10.10.0.0/21`, `10.20.0.0/24`, `10.30.0.0/24`. (For unauthenticated entry vectors that come *before* recon, see [`02a-initial-access.md`](02a-initial-access.md).)

---

### REC-001 — Domain Enumeration (LDAP / ADWS)
**What it is:** the most basic and most powerful AD discovery primitive — pull every user, group, computer, OU, GPO from the DC using anonymous or authenticated LDAP. AD is read-mostly by design: Authenticated Users have read on essentially everything.
**Why it works here:** AD default. We didn't restrict it.
**Tools:** `ldapsearch`, `nxc ldap`, `pywerview`, `Get-ADUser`, `Get-DomainUser` (PowerView).
**Steps:**
```bash
# anonymous (yes, often allowed)
ldapsearch -x -H ldap://10.10.0.10 -b "DC=corp,DC=local" -s sub "(objectClass=user)" sAMAccountName

# authenticated
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --users
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --groups
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --computers

# PowerView (on ws01)
Import-Module .\PowerView.ps1
Get-DomainUser | Select samaccountname, description
Get-DomainGroup -AdminCount 1
Get-DomainComputer -Properties dnshostname, operatingsystem
```
**Detection:** Event ID `4662` (operation on object) at high volume from a single SID, Event `1644` (LDAP query) if logged. Look for queries matching SharpHound's signature (`(|(samAccountType=805306368)...)`).
**Prevention:** you can't remove read for Authenticated Users without breaking AD. Monitor for *bulk* enumeration (>500 LDAP queries / 5 min from one principal). Microsoft ATA/Defender for Identity does this natively.

---

### REC-002 — SPN Enumeration
**What it is:** find every service-principal-name on every account. SPN + user account = Kerberoastable; SPN + computer account = service host. This is step 0 of any Kerberoast.
**Why it works here:** AD default; SPNs are world-readable.
**Tools:** `impacket-GetUserSPNs`, `Rubeus`, `setspn`.
**Steps:**
```bash
impacket-GetUserSPNs corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10
# windows
setspn -Q */*
# Rubeus
.\Rubeus.exe kerberoast /stats   # just list, no roast yet
```
**Detection:** LDAP query for `(servicePrincipalName=*)` — Event ID `4662`. Defender for Identity raises "reconnaissance using directory services queries."
**Prevention:** none — SPNs must be visible for Kerberos to work. Defense is making roasting non-viable: long random passwords on service accounts, or gMSAs.

---

### REC-003 — BloodHound / SharpHound ingest
**What it is:** automated collection of every user, group, computer, ACL, GPO link, session, and trust into a Neo4j graph. The graph then computes shortest paths to Domain Admin.
**Why it works here:** any authenticated user can collect.
**Tools:** `SharpHound.exe` (Windows), `bloodhound-python` (Linux), BloodHound CE/Legacy GUI.
**Steps:**
```bash
# Linux
bloodhound-python -u peter.parker -p 'DVADlab2024!' -d corp.local -ns 10.10.0.10 -c all
# Windows
.\SharpHound.exe -c All --domain corp.local
# upload zips into BloodHound, then run "Find Shortest Paths to Domain Admins"
```
**Detection:** SharpHound has a heavy collection footprint — LDAP queries, SMB session queries on every computer (`NetSessionEnum`, `NetWkstaUserEnum`), bursts of port-445 connects. Microsoft Defender for Identity has a dedicated SharpHound rule.
**Prevention:** `Net Cease` (removes anonymous `NetSessionEnum`); restrict `NetWkstaUserEnum` via the registry key `RestrictRemoteSAM`.

---

### REC-004 — Trust Enumeration
**What it is:** discover every trust this forest has (parent-child, tree-root, external, forest, shortcut). Trusts are the bridges to cross-forest attacks.
**Why it works here:** trusts are public information in AD.
**Tools:** `nltest`, `Get-ADTrust`, `Get-DomainTrust`, `nxc ldap --trusted-for-delegation`.
**Steps:**
```powershell
nltest /domain_trusts /all_trusts
Get-ADTrust -Filter *
Get-DomainTrust -SearchBase "DC=corp,DC=local"
```
```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --trusted-for-delegation
```
**Detection:** LDAP queries against `CN=System,DC=corp,DC=local` / `trustedDomain` objects.
**Prevention:** enable **SID filtering** on every external/forest trust (we *disabled* it deliberately). Use selective authentication where possible.

---

### REC-005 — GPO Enumeration
**What it is:** list every GPO and where it's linked. GPOs that drop scheduled tasks, scripts, or registry settings often contain juicy paths or even passwords.
**Why it works here:** SYSVOL is world-readable.
**Tools:** `gpresult`, `Get-GPO`, `Get-DomainGPO` (PowerView), `Get-GPOReport`.
**Steps:**
```powershell
Get-GPO -All | Select DisplayName, Id
Get-DomainGPO | Get-DomainGPOLocalGroup       # find machines where you'd land as local admin
Get-DomainGPOComputerLocalGroupMapping        # the inverse
gpresult /SCOPE COMPUTER /Z > gp.txt
```
**Detection:** SMB reads from `\\domain\SYSVOL\Policies\` at unusual volume.
**Prevention:** keep SYSVOL clean — no passwords, no clear-text secrets, no overly-broad delegation (`Authenticated Users` write to a GPO is a backdoor).

---

### REC-006 — ACL Enumeration
**What it is:** read the DACLs on every AD object. Over-permissive ACLs (`GenericWrite`, `WriteDACL`, `Reset-Password`) on privileged objects are the #1 path to DA in modern AD.
**Why it works here:** ACLs are world-readable on AD objects.
**Tools:** `BloodHound` (best graph view), `Get-DomainObjectAcl`, `Get-Acl AD:` (RSAT).
**Steps:**
```powershell
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
  ? { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDACL' }
# DCSync rights:
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs |
  ? { $_.ObjectAceType -match 'DS-Replication-Get-Changes' }
```
**Detection:** none reliable — ACL reads are just LDAP queries.
**Prevention:** routinely audit with BloodHound; remove `Authenticated Users`/`Domain Users` from privileged ACEs; tier your admin model.

---

### REC-007 — DNS Zone Transfer (AXFR)
**What it is:** ask the DC to dump its entire DNS zone over TCP/53. Gives you every internal hostname for free.
**Why it works here:** we left zone transfers unrestricted (intentional).
**Tools:** `dig`, `nslookup`, `nxc`.
**Steps:**
```bash
dig @10.10.0.10 corp.local AXFR
dig @10.10.0.10 _ldap._tcp.dc._msdcs.corp.local SRV
nslookup -type=ANY corp.local 10.10.0.10
```
**Detection:** Microsoft DNS logs AXFR via Event `6001`/`6004`. Sigma has rules for "DNS Zone Transfer."
**Prevention:** in DNS Manager, set zone transfers to "Only to servers listed on the Name Servers tab." Better: disable entirely if you don't have secondaries.

---

### REC-008 — SMB Share Enumeration
**What it is:** list shares on every host and try to read them with null / guest / authenticated sessions. The classic ways into a network — old scripts left on `\\file01\Public`, GPP `Groups.xml` in SYSVOL.
**Why it works here:** Guest enabled, anonymous SMB allowed for legacy compatibility.
**Tools:** `smbclient`, `nxc smb --shares --spider`, `smbmap`.
**Steps:**
```bash
smbclient -L //10.10.0.13 -N                      # null
nxc smb 10.10.0.0/24 -u peter.parker -p 'DVADlab2024!' --shares
nxc smb 10.10.0.13 -u peter.parker -p 'DVADlab2024!' --spider Public --pattern '\.txt|\.ps1|\.bat|password'
smbmap -H 10.10.0.13 -u peter.parker -p 'DVADlab2024!' -R Public
```
**Detection:** Event ID `5140` (network share accessed) at high volume.
**Prevention:** disable Guest (`net user guest /active:no`), disable `RestrictNullSessAccess=1`, enable SMB signing required.

---

### REC-009 — MSSQL Instance Enumeration
**What it is:** SQL Server Browser broadcasts every named instance on UDP/1434. Combined with `PowerUpSQL` you discover every reachable database, then check for `xp_cmdshell` or trust links.
**Why it works here:** SQL Browser is on, instances are unsigned.
**Tools:** `PowerUpSQL`, `nxc mssql`, `impacket-mssqlclient`.
**Steps:**
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                      # finds via SPN
Get-SQLInstanceScanUDP -ComputerName sql01 # UDP/1434 broadcast
Get-SQLServerInfo -Instance sql01.corp.local
Get-SQLServerLinkCrawl -Instance sql01 -Verbose   # link chain
```
```bash
nxc mssql 10.10.0.14 -u peter.parker -p 'DVADlab2024!' --local-auth
```
**Detection:** SQL Server logs failed logins (Event `18456`). Defender for Identity has SQL discovery alerts.
**Prevention:** disable SQL Browser service. Force Windows-only auth. Disable `xp_cmdshell`.

---

### REC-010 — LLMNR / NBT-NS Poisoning preflight
**What it is:** verify the network broadcasts LLMNR / NBT-NS / mDNS. If a host fails DNS, it broadcasts the name lookup; Responder answers and harvests NTLMv2 hashes. Step 1 is just listening.
**Why it works here:** intentional — we leave both protocols enabled.
**Tools:** `Responder` (listen-only mode), `tcpdump`.
**Steps:**
```bash
sudo responder -I virbr1 -A                            # analyze mode, no poison
sudo tcpdump -i virbr1 'udp and (port 137 or port 5353 or port 5355)'
```
**Detection:** Microsoft Defender for Identity has "Suspected Responder/LLMNR poisoning" alerts. Sysmon Event `22` (DNS lookup).
**Prevention:** GPO disable LLMNR (`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0`) + disable NBT-NS per-NIC. Set a DNS suffix search list so hosts don't fall through to broadcast.

---

### REC-011 — Password Policy Enumeration
**What it is:** read the Default Domain Policy to know the lockout threshold *before* you spray. Knowing it = not getting locked out.
**Why it works here:** policy is readable by Authenticated Users.
**Tools:** `net accounts /domain`, `Get-ADDefaultDomainPasswordPolicy`, `nxc smb --pass-pol`.
**Steps:**
```bash
nxc smb 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --pass-pol
```
```powershell
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *      # PSO that overrides default
```
**Detection:** none reliable.
**Prevention:** none needed; this is by design. Defense is to set lockout threshold > 0 (we set it to 0).

---

### REC-012 — ADCS Template Enumeration
**What it is:** list every certificate template published on `ca01.corp.local`, with EKU, enrollment rights, and flags. This is step 0 of ESC1-16.
**Why it works here:** template ACLs allow Domain Users to read.
**Tools:** `Certify.exe`, `Certipy find`, `certutil`.
**Steps:**
```bash
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -enabled -vulnerable -stdout
```
```powershell
.\Certify.exe find /vulnerable
.\Certify.exe find /clientauth     # only templates with Client Auth EKU
certutil -dctemplate -dc dc01.corp.local
```
**Detection:** LDAP queries against `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local`.
**Prevention:** review template DACLs; remove `Authenticated Users`/`Domain Users` from Enroll on any template with Client Auth EKU.

---

### REC-013 — Kerberos Pre-auth Enumeration (AS-REP)
**What it is:** find every account with `DONT_REQUIRE_PREAUTH`. Each one will accept an unauthenticated AS-REQ and return an AS-REP encrypted with the user's key — directly crackable.
**Why it works here:** `corp\svc_nopreauth` (and others) have this set.
**Tools:** `impacket-GetNPUsers`, `Rubeus asreproast`.
**Steps:**
```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hashes
# or authenticated:
impacket-GetNPUsers corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10 -request -format hashcat
```
```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes
```
**Detection:** Event ID `4768` with `Pre-Authentication Type: 0`. Defender for Identity has an alert for it.
**Prevention:** clear `DONT_REQ_PREAUTH` on every account: `Set-ADAccountControl -Identity user -DoesNotRequirePreAuth $false`.

---

### REC-014 — Machine Account Enumeration
**What it is:** list every computer object. Each has a password (the machine secret); each is a Silver Ticket target.
**Why it works here:** computer objects are public.
**Tools:** `Get-ADComputer`, `Get-DomainComputer`, `nxc ldap`.
**Steps:**
```powershell
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, ms-DS-MachineAccountQuota
Get-DomainComputer -Unconstrained                       # unconstrained delegation targets
Get-DomainComputer -TrustedToAuth                       # constrained delegation
```
**Detection:** none reliable.
**Prevention:** `MachineAccountQuota=0` (we set to 10 deliberately) so users can't add new computers.

---

### REC-015 — Sensitive Data in SYSVOL / NETLOGON
**What it is:** SYSVOL contains login scripts and (historically) Group Policy Preferences `Groups.xml` with the `cpassword` AES key (MS14-025, MS reverses but doesn't remove). Greppable goldmine.
**Why it works here:** SYSVOL is Authenticated Users read; we leave legacy GPP files in place.
**Tools:** `Get-GPPPassword`, `findstr`, `grep`.
**Steps:**
```bash
# Linux mount or smb spider:
nxc smb 10.10.0.10 -u peter.parker -p 'DVADlab2024!' \
   --spider SYSVOL --pattern 'cpassword|password|netuse'
```
```powershell
Get-GPPPassword                                    # decrypts cpassword to clear
findstr /S /I "password" \\corp.local\sysvol\*.*
```
**Detection:** Event `5140` for SYSVOL access at high volume.
**Prevention:** remove all `Groups.xml`/`Drives.xml`/etc with `cpassword`. Don't put secrets in SYSVOL. Period.

---

Next: [`03-credential-access.md`](03-credential-access.md).
