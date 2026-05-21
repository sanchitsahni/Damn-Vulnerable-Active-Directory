# DVAD Study Curriculum — Zero to Domain Admin

A self-contained study course that takes you from **never having logged into a Windows machine** to **owning a multi-forest Active Directory lab**. The DVAD lab in this repo is the practical playground; every chapter ends with exercises that map to specific DVAD flag IDs.

**Prerequisites for reading this curriculum:**
- You can use a Linux terminal at a basic level (`cd`, `ls`, `grep`).
- You know what an IP address is.
- That's it. We assume zero Windows, AD, PowerShell, or Kerberos knowledge.

**Time budget:** ~80–140 hours if you do every exercise. ~30 hours if you skim.

---

## 0. Quick-start

If you just want to start *now*:

1. Read **§ How to use this curriculum** below (5 min).
2. Skim the **§ Table of contents** to see what's coming (5 min).
3. Read the **§ Five reading paths** to pick yours (5 min).
4. Open [01-foundations.md](01-foundations.md) and start.

The rest of this file is reference — chapter abstracts, glossary, FAQ, conventions. Come back when you need to.

---

## How to use this curriculum

1. Read the chapters in order. They build on each other.
2. After each chapter's *Theory* section, run the *Lab exercises* on a deployed DVAD lab (`./deploy.sh`).
3. Each exercise references a flag ID from `PLAN.md`. Capture the flag file at `C:\Flags\<ID>.txt` on the target host to confirm you executed the technique.
4. At the end of each chapter you'll find *Self-check questions*. If you can't answer them, re-read.
5. The *References* section lists primary sources (Microsoft docs, RFCs, MS-OPEN protocol specs, and the canonical research papers). Skim them at minimum.
6. Keep a notebook (markdown file works fine). After each chapter, write 5–10 lines summarising what you actually retained. The act of writing is the actual learning step.

### A typical session

```
T+0:00  Open chapter
T+0:05  Read theory, take a few notes
T+1:30  Hit the first lab exercise — pause reading, do the exercise
T+2:30  Continue reading
T+3:30  Do the next exercise
T+4:30  Stop. Write a 5-line summary of what you learned today.
```

Three to four hours per session, three sessions per week, is sustainable. Eight-hour cram sessions are not — Active Directory has too many concepts to absorb in one sitting and you'll forget most of it by the next day.

### When to stop and look something up

If a paragraph mentions a term you've never heard, don't gloss over it. Stop. Open a new tab. Search. Add the term to the glossary in §17 of this file with your own one-line definition. AD has hundreds of small terms ("KCC," "FRS," "NLA," "IFM," "WMI repository") and you'll see them again — better to learn each one the first time than to half-recognise them every time.

---

## Table of contents

| # | File | What you learn | Lines | Hours |
|---|---|---|---|---|
| 00 | [00-index.md](00-index.md) | This file. How to study, prerequisites, conventions, glossary, FAQ. | ~1700 | 1 |
| 01 | [01-foundations.md](01-foundations.md) | Networking refresher, DNS, TCP/IP, packet flow, Wireshark intro. The OS-agnostic primitives every later chapter assumes. | ~1500 | 6 |
| 02 | [02-windows-internals.md](02-windows-internals.md) | Windows from scratch: NT kernel, processes, SIDs, tokens, ACLs, registry, services, the SAM database, LSASS. | ~1700 | 10 |
| 03 | [03-powershell.md](03-powershell.md) | PowerShell from `Write-Host "hello"` to PowerView. Objects, pipeline, scriptblocks, remoting, AD module, PowerView/PowerSploit. | ~1500 | 10 |
| 04 | [04-active-directory.md](04-active-directory.md) | What AD *is*. Forests, domains, OUs, the schema, replication, the global catalog, FSMO roles, trusts, sites. Why it exists. | ~1600 | 12 |
| 05 | [05-authentication-protocols.md](05-authentication-protocols.md) | NTLM, LM, NetNTLMv1/v2, Kerberos in full RFC depth: AS/TGS, PAC, S4U2Self/Proxy, FAST, PKINIT, U2U, referrals across trusts. | ~1900 | 14 |
| 06 | [06-pki-and-adcs.md](06-pki-and-adcs.md) | PKI from first principles: RSA, X.509, CSRs, certificate chains. Then ADCS: enrollment, templates, EKUs, every ESC1–ESC16. | ~1900 | 10 |
| 07 | [07-attacker-toolkit.md](07-attacker-toolkit.md) | Every tool you'll use: impacket, certipy, BloodHound, mitm6, Responder, ntlmrelayx, Rubeus, mimikatz, netexec, evil-winrm, hashcat. With per-flag examples. | ~1900 | 10 |
| 08 | [08-recon-and-enum.md](08-recon-and-enum.md) | Methodical enumeration: port scan → SMB → LDAP → Kerberos → DNS → ADCS → SQL. The 80 ENUM flags. | ~1500 | 8 |
| 09 | [09-initial-access.md](09-initial-access.md) | The 50 IA techniques: from broadcast poisoning to anonymous binds to relay chains. How attackers get the first credential without one. | ~1200 | 8 |
| 10 | [10-credential-access.md](10-credential-access.md) | Roasting, DCSync, DPAPI, LSASS, coercion (PetitPotam/PrinterBug/DFSCoerce), NTLM relay, cert theft. Every CRED-* technique. | ~1400 | 10 |
| 11 | [11-lateral-and-privesc.md](11-lateral-and-privesc.md) | Lateral movement (PSExec, WMI, DCOM, WinRM, RDP, SSH, PTH/PTT) and privilege escalation (tokens, services, AD privileges, ADCS misuse). | ~1100 | 10 |
| 12 | [12-persistence-and-forest.md](12-persistence-and-forest.md) | Golden/Silver/Diamond/Sapphire tickets, AdminSDHolder, DCShadow, Skeleton key, SID history, trust ticket forging, child→root, Certifried. | ~1400 | 10 |
| 13 | [13-defense-and-detection.md](13-defense-and-detection.md) | Why each vuln exists, how to fix it, what the detection looks like in Event Log / Sysmon / Defender. So you understand the other side. | ~1100 | 6 |
| 14 | [14-capstone.md](14-capstone.md) | End-to-end capstone: solve DVAD from zero credentials to enterprise admin across all three forests, using everything you've learned. | ~1200 | 8 |

**Total: ~140 hours of material**, but most of it is exercises you do at your own pace.

---

## Chapter abstracts

Each chapter abstract below answers three questions: *what's in it*, *what skill you build*, and *what the prerequisite is*. Read these before deciding to skip a chapter.

### Chapter 01 — Foundations

**What's in it:** OSI model, TCP/IP basics, IP/MAC/ARP, switching/routing/NAT, DHCP, DNS in detail (record types, recursive vs iterative, SRV records, AD-Integrated DNS), HTTP/HTTPS, TLS handshake, packet capture with `tcpdump` and Wireshark, common ports table, IPv4 vs IPv6 (and why mitm6 matters).

**Skill built:** You can read a packet capture and explain what's happening. You can use `dig` to resolve any record type. You know why broadcast traffic exists and how Responder uses it.

**Prerequisite:** Linux shell basics.

**Why it matters for AD:** Every AD attack ultimately travels on a network packet. If you can't tell SMB from LDAP from Kerberos at the packet level, you'll be confused for chapters 5+.

### Chapter 02 — Windows internals

**What's in it:** Kernel vs user mode, processes and threads, the NT object manager (handles, securable objects), SIDs (well-known SIDs, RIDs, the structure), tokens (primary vs impersonation, types, access masks), ACLs (ACEs, inheritance, audit ACEs), the registry hierarchy, the Windows service model (SCM, service accounts, start types), the SAM database, LSASS (what it stores, why attackers want it), the security subsystem (LSA, NTLM SSP, Kerberos SSP, Negotiate, SChannel).

**Skill built:** You can read a security event log line and decode every field. You can explain why mimikatz attacks `lsass.exe` and not `winlogon.exe`.

**Prerequisite:** Chapter 01.

**Why it matters:** AD is, fundamentally, a distributed extension of the Windows security model. You can't attack what you don't understand the structure of.

### Chapter 03 — PowerShell

**What's in it:** Why PowerShell exists, the object pipeline (vs text), cmdlet naming, scriptblocks, advanced functions, error handling, sessions/remoting (PSSession, Invoke-Command, JEA), the AD module (`ActiveDirectory`), the GroupPolicy module, PowerView (`Find-Domain*`, `Invoke-Kerberoast`, `Add-DomainObjectAcl`), PowerSploit, AMSI bypass concepts, ScriptBlock logging (4104), Constrained Language Mode.

**Skill built:** You can write a one-line PowerShell that walks LDAP, opens a remote session, or enumerates ACLs. You can read most attacker PowerShell scripts on first pass.

**Prerequisite:** Chapter 02.

**Why it matters:** Half the AD red-team tooling is PowerShell. Half the defender's audit tooling is PowerShell. It's the lingua franca.

### Chapter 04 — Active Directory

**What's in it:** What AD *is* (a distributed database + auth service). Forest/domain/OU hierarchy. The schema (objectClass, attributes, syntaxes, mandatory vs optional). Replication (DRSR, USN, change tracking, urgent vs scheduled). The Global Catalog (which attributes, why useful). FSMO roles (PDC Emulator, RID Master, Infrastructure Master, Schema Master, Domain Naming Master) — what each does and why losing one is bad. Sites and replication topology. Trusts (forest, external, parent-child, shortcut, realm) with `trustAttributes` bits. The "well-known" containers (Users, Computers, Domain Controllers, AdminSDHolder, etc.). The Configuration NC and Schema NC.

**Skill built:** You can draw the forest map of any AD deployment from a few LDAP queries. You can explain why Enterprise Admins is more powerful than Domain Admins.

**Prerequisite:** Chapter 02 (SIDs/ACLs) + Chapter 01 (DNS).

**Why it matters:** This is the foundation chapter for every offence and defence chapter after it.

### Chapter 05 — Authentication protocols

**What's in it:** LM (and why it died), NTLMv1, NTLMv2, NTLM challenge-response with worked examples. The full Kerberos exchange (AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, AP-REP) with packet field detail. Pre-authentication. The PAC (LOGON_INFO, sigs). S4U2Self, S4U2Proxy. Constrained, unconstrained, RBCD delegation. PKINIT. FAST. U2U. Cross-realm referrals. Encryption types (RC4, AES128, AES256, DES) and the etype-negotiation bug class.

**Skill built:** You can explain every step a user goes through when they double-click `\\fileserver\share\file.txt`, byte-roughly. You can derive a session key on paper.

**Prerequisite:** Chapter 04 (you need to know what a domain controller is) + Chapter 01 (TCP/UDP packets).

**Why it matters:** Every "advanced AD attack" is a manipulation of one of these protocols.

### Chapter 06 — PKI and ADCS

**What's in it:** RSA (key generation, sign/verify, why padding matters). X.509 (the DER structure, the fields, the extensions). CSRs. Certificate chains, root CAs, intermediate CAs. CRL and OCSP. The ADCS architecture (Enterprise CA, Stand-alone CA, the templates, the enrollment endpoints — RPC, DCOM, HTTP, HTTPS). PKINIT and how AD uses certs. Every ESC1–ESC16 in depth (the technique, the precondition, the impact, the fix).

**Skill built:** You can read a cert template's flags and decide if it's vulnerable to ESC1 in 30 seconds. You can chain a coercion + relay + cert auth into Domain Admin.

**Prerequisite:** Chapter 05 (PKINIT requires Kerberos understanding).

**Why it matters:** ADCS is the single most common path to DA in modern AD assessments. Microsoft has been patching ESCs for two years and there are still environments with vulnerable templates from 2009.

### Chapter 07 — Attacker toolkit

**What's in it:** A guided tour of every tool the lab and the field use. Impacket (full script index with examples), certipy, BloodHound (collectors + GUI + Cypher), mitm6, Responder, ntlmrelayx, Rubeus, mimikatz, netexec/nxc, evil-winrm, hashcat (every relevant `-m` mode), john, bloodyAD, kerbrute, ldapdomaindump, ldeep, certify, SharpHound, SharpGPOAbuse, Whisker, Cobalt Strike + open-source C2 alternatives at a survey level.

**Skill built:** You can pick the right tool from any of the 30 in your toolkit, in seconds. You understand what each tool is doing under the hood enough to debug it when it fails.

**Prerequisite:** Chapters 05 + 06 (to understand the *content* of the tools' output).

**Why it matters:** A toolkit you can't reason about is a toolkit that abandons you when something doesn't work.

### Chapter 08 — Recon and enumeration

**What's in it:** The 16-layer recon pyramid from "an IP range" to "a complete BloodHound graph + cert template inventory + share map + session map + trust map." Anonymous LDAP, RID cycling, authenticated enum, BloodHound collection, ADCS enum with certipy, per-host service enum, SYSVOL trawl, LAPS/gMSA enum, trust enum, session enum (NetSessionEnum vs NetWkstaUserEnum), RPC enum, per-user self-ACL, Configuration NC PKI walk, GC queries, service-account heuristics, privileged group catalogue, cross-tier visibility analysis.

**Skill built:** A reproducible recon process that finishes with a complete picture of any AD environment in 2-4 hours.

**Prerequisite:** Chapter 07 (tools).

**Why it matters:** Bad recon = wasted attack attempts on unviable paths. Good recon makes the attack feel obvious.

### Chapter 09 — Initial access

**What's in it:** The 7 onramps to first credential without any starting credential — LLMNR/NBT-NS poisoning, anonymous services, coercion+relay chains, pre-auth Kerberos/cert paths, public leaks (SYSVOL GPP), weak service auth, direct CVEs (ZeroLogon, PrintNightmare, noPac). The full Responder + ntlmrelayx + PetitPotam + mitm6 + ESC8 cookbook.

**Skill built:** Given any "unknown network with AD," you can walk through the 50 IA flags and decide which two or three apply this hour.

**Prerequisite:** Chapter 08 (you need recon output to choose IA paths).

**Why it matters:** The hardest part of an engagement is often "the first foothold." This chapter eliminates the mystery.

### Chapter 10 — Credential access

**What's in it:** Roasting (Kerberoast, AS-REP roast, targeted Kerberoast, etype downgrade), DCSync (mechanics, ACE GUIDs, secretsdump worked example), LSASS dumping (5 methods with stealth tradeoffs), DPAPI (master keys, backup pvk, gMSA via DPAPI-NG), coercion+NTLM relay (every target service), RBCD via MAQ, shadow credentials, ADCS ESC abuse for cred access (CRED-022..037), MSSQL paths (xp_cmdshell, xp_dirtree, IMPERSONATE, TRUSTWORTHY, linked servers), gMSA, LAPS, PTH/PTK/PTT/PTC/Overpass, vault/RDP/browser/KeePass, DCC2/mscash2, PFX cracking, the full hashcat mode table.

**Skill built:** Given any user/host you have a foothold on, you can list the 5-10 credentials you'd try to extract first.

**Prerequisite:** Chapter 09 (you need a foothold to attack from).

**Why it matters:** Credentials are the currency of AD attacks. This chapter is about the mint and the wallets.

### Chapter 11 — Lateral movement and privilege escalation

**What's in it:** Lateral primitives (psexec, wmiexec, smbexec, dcomexec, atexec, evil-winrm) at the protocol-and-event-log level. PTH/PTK/PTT. The Potato family (JuicyPotato, RoguePotato, PrintSpoofer, GodPotato, EfsPotato, DCOMPotato). Service binary hijack, unquoted path, DLL hijack, AlwaysInstallElevated, scheduled task hijack. AD-group escalation (Backup Operators, Server Operators, Print Operators, Account Operators, DnsAdmins, GPO Creator Owners, Cert Publishers, Schema Admins). AdminSDHolder. GPO abuse (SharpGPOAbuse + pyGPOAbuse). The 12-row ACL abuse table. Per-DVAD-host PE paths. Token impersonation. LOLBAS catalog. UAC bypass. AV/Defender exclusion. In-process LSASS theft (lsassy/nanodump/MalSecLogon).

**Skill built:** From local user on any host, you have ten ways to become SYSTEM, plus a decision tree for which one to pick based on the environment.

**Prerequisite:** Chapter 10 (you need a credential to laterally move).

**Why it matters:** "I got a shell" is rarely the goal. "I got SYSTEM on the DC" is. This chapter is the climb.

### Chapter 12 — Persistence and forest compromise

**What's in it:** The persistence ladder (forest-wide / domain-wide / object-scoped / host-local) with cost-vs-survival matrix. Golden tickets (with opsec knobs). Silver tickets (with limitations). Diamond and Sapphire tickets. Why krbtgt is the keys to the kingdom. AdminSDHolder backdoor. DCShadow attribute push. Skeleton key. Certificate persistence. Shadow credentials persistence. GPO-based persistence. SID history injection. Inter-forest trust-ticket forge. Child→Root via SID history. Cross-child (eu.corp.local) via SID history. Forest persistence via ADCS. Schema modification. Security descriptor backdoor on domain root. Trust account password backdoor. 17 host-local persistence techniques. Token operations as logon hijack persistence.

**Skill built:** You can plant a persistence stack that survives password resets, krbtgt rotations, DC rebuilds, EDR rollouts, and most ACL audits.

**Prerequisite:** Chapter 11 (you need to be DA to persist).

**Why it matters:** Persistence is what separates a one-shot CTF from a real engagement. Forest compromise is what separates "an AD test" from "a forest-wide breach."

### Chapter 13 — Defense and detection

**What's in it:** The defender's data sources. Why intentionally vulnerable defaults persist (NTLM, LLMNR, MAQ=10, DCSync ACEs). Per-attack detection: roasting (Sigma + KQL), DCSync (4662 + GUID), NTLM relay (relay signal + coercion signal), ADCS (4886/4887 with SAN mismatch, per-ESC table), Golden/Silver/Diamond/Sapphire (correlation logic), lateral movement (per-tool detection table), LSASS access (mask cheat sheet, mitigations), DCShadow, AdminSDHolder, ZeroLogon, noPac, shadow credentials, RBCD, GPO implants, PrintNightmare, skeleton key, krbtgt rotation. Honey tokens (10 types). The defender's playbook (18-item priority list). Cost-vs-value matrix. Detection engineering as iterative process. MITRE ATT&CK mapping.

**Skill built:** You can write a Sigma rule for any attack you can execute. You can predict where a defender will see your activity and adjust opsec accordingly.

**Prerequisite:** Chapters 9-12 (you need to know the attacks to detect them).

**Why it matters:** Operators who don't know detection get caught. Defenders who don't know offence build bad rules. This chapter closes both gaps.

### Chapter 14 — Capstone

**What's in it:** Operational mindset (workspace, naming conventions, tooling baseline). The 10-phase end-to-end engagement on DVAD (recon → first cred → authenticated enum → DA on corp.local → persistence stack → lateral sweep → child domain → forest root via SID history → external forest via trust ticket forge → loot consolidation). Side quests (the long tail of remaining flags). The 2-hour critical path. Cleanup checklist. Report writing template. Self-assessment checklist. What to read next.

**Skill built:** You can execute a complete forest compromise on muscle memory, document it as a real engagement would, and explain every step.

**Prerequisite:** All previous chapters.

**Why it matters:** This is the consolidation. Everything you've learned, executed in order, against a real (synthetic) environment, with proper documentation and cleanup.

---

## Five reading paths

Different readers have different starting points and goals. Pick the path that fits.

### Path A — Total beginner (recommended)

Read every chapter in order. Do every lab. Allocate 80–140 hours over 3–6 months. Don't rush.

### Path B — Experienced Linux/security person new to Windows AD

Skim chapter 01 (you know networking). Read chapters 02–04 carefully (Windows specifics). Then proceed normally from 05. Total ~80 hours.

### Path C — Junior pentester who has done HTB but is shaky on AD theory

Skim chapters 01–03. Read 04–06 carefully. Skim 07. Read 08–14 carefully. Total ~60 hours.

### Path D — Defender / SOC analyst wanting offensive insight

Skim chapters 01–04. Read 05–06 carefully. Skim 07–08. Read 09–12 *carefully* (the attacks you'll detect). Read 13 *very carefully* (your domain). Skim 14. Total ~50 hours.

### Path E — Speedrun (you have an interview in two weeks)

Read chapters 04, 05, 06, 08, 09, 10, 11, 12, 14. Skip the rest. Total ~30 hours and dense. Not recommended but possible.

---

## Conventions used throughout

### Code blocks

- `# linux-prompt` style means run this on **your attacker box** (Kali on the host, or a WireGuard peer).
- `PS C:\>` means run this in **PowerShell on a Windows VM** (typically via WinRM / RDP after compromise).
- `mimikatz #` means inside a mimikatz session.
- Lines starting with `# ` *inside* a code block are comments, not output. Lines without `#` and without a prompt are typically output.

### Ascii diagrams

We draw things like this:

```
+--------------+         AS-REQ (encrypted with user's key)         +--------------+
|              | --------------------------------------------------> |              |
|   Client     |                                                      |     KDC      |
|  (alice)     | <-------------------------------------------------- | (dc01.corp)  |
|              |   AS-REP (TGT encrypted with krbtgt's key + sess.)  |              |
+--------------+                                                      +--------------+
```

Read them with a fixed-width font.

### Flag references

When we write `[Flag: CRED-001]` it means doing the technique we just discussed will capture the file `C:\Flags\CRED-001.txt` on the host that contains the flag. The host is listed in `PLAN.md`. See [11-lateral-and-privesc.md](11-lateral-and-privesc.md) §0 for how to read flag files once you have access.

### Levels of detail

We label sections with depth:

- **(Concept)** — high-level "what is this and why does it matter."
- **(Mechanics)** — how it works under the hood (packet fields, registry keys, function calls).
- **(Exploit)** — how attackers abuse it.
- **(Defense)** — how it should be configured securely + what detection looks like.

Skip Mechanics on first pass if you're impatient. Don't skip them forever — they're what separates a script kiddie from an operator who can adapt when tooling fails.

### Inline references

When you see `[MS-KILE]` or `RFC 4120` in the prose, that's a primary source. The chapter's References section at the end has the link. We don't repeat URLs inline because they bit-rot.

### Terminology

When a term has multiple common names, we pick one and stick with it, but mention the others:

- **netexec / nxc / CrackMapExec / cme:** we use `nxc` (the current binary name).
- **secretsdump / impacket-secretsdump:** we use `impacket-secretsdump` for clarity.
- **ATA / ATP / MDI / Defender for Identity:** we use **Defender for Identity (DfI)** — same product, three rebrands.
- **Microsoft Identity Manager / FIM / Forefront Identity Manager:** we use **MIM**.

---

## What this curriculum is NOT

- **Not a Microsoft certification track.** We cover what's needed for offense; we skip GPO design, Hyper-V replicas, Azure AD Connect rate limits, etc.
- **Not legal advice.** DVAD is for testing in environments you own. Everything in this material is illegal to perform against systems you don't have written authorization to attack.
- **Not a substitute for primary sources.** When we cite an RFC, *read it*. When we cite a SpecterOps blog post, *read it*. We summarize so you have the map; the territory is in the references.
- **Not focused on Azure AD / Entra ID.** This curriculum covers *on-premises Active Directory*. Azure AD / Entra ID is a different (though related) world with different attack surface (consent grants, application secrets, conditional access, OAuth flows). DVAD does not deploy Azure resources.
- **Not a CTF cheat sheet.** We explain why things work, not just commands to type. If you just want commands, `WALKTHROUGH.md` in the repo root does that.

---

## A note on learning style

People learn AD wrong because they jump into BloodHound and Rubeus before understanding what a "domain" *is*. They memorize commands but can't recover when a tool breaks.

The right order:

1. **Domain concepts first.** What is a forest? What is replication? What does a "trust" mean at the LDAP/Kerberos layer? Chapter 04 is the longest chapter for a reason.
2. **Authentication second.** How does a user actually log in? What is a TGT made of? Chapter 05 covers Kerberos in RFC depth because every interesting AD attack manipulates it.
3. **Tooling last.** Once you know the protocols, every tool is just a wrapper. You won't be confused when one fails.

Resist the urge to skip to Chapter 11. The investment up-front pays off massively.

### Why this order works

The reason most online AD courses fail is they're optimised for "look at this cool exploit" rather than "explain why this exploit works." The result: you can run `impacket-GetUserSPNs` but you can't explain what etype downgrade means, so when an environment hardens RC4 and your roast doesn't crack, you're stuck.

This curriculum is optimised for the second case: when something doesn't work, you can debug from first principles. Every chapter ends with self-check questions; if you can't answer them, that's exactly the point where you should re-read.

### The "I'm bored" failure mode

The first three chapters are the hardest to stay engaged through because they're abstract — you're not popping shells yet. The motivation to push through is:

- Chapter 04 has the first "interesting" AD content.
- Chapter 05 has the first "I see why people care about this" moments (PAC, S4U).
- Chapter 06 is where you start saying "wait, that's a vulnerability?"

If you make it to chapter 05, the rest carries you. Most people who quit, quit at chapter 03.

### The "I'm overwhelmed" failure mode

The middle chapters (05–07) are dense. If you're feeling lost:

- Skim, don't read. Get the map first, fill in detail later.
- Do the exercises *first* before re-reading. Practice will surface what you actually need.
- Skip the (Mechanics) sections on first pass.
- Take a week off and come back. The brain consolidates AD concepts surprisingly well during downtime.

---

## Companion files in this repo

- `PLAN.md` — Authoritative list of 382 vulnerabilities/flags. Use as a checklist.
- `WALKTHROUGH.md` — 5100-line end-to-end solve guide. Use after each chapter to see techniques in action.
- `ad-architechture.html` — Visual companion to PLAN.md. Open in a browser.
- `docs/` — Per-host crib sheets, deployment notes, VPS guide.
- `STUDY/` — *(this curriculum)*

Start with [01-foundations.md](01-foundations.md). Good luck.

---

## Glossary

A flat list of every acronym, term, and noun used across this curriculum. If you see something in a chapter you don't recognise, search here first.

| Term | Definition |
|---|---|
| **AAA** | Authentication, Authorization, Accounting. The three pillars of access control. |
| **AAD / Entra ID** | Microsoft's cloud identity service. Not covered in this curriculum. |
| **ACE** | Access Control Entry. One row in an ACL. |
| **ACL** | Access Control List. The DACL is "who can do what"; the SACL is "what to audit." |
| **ADCS** | Active Directory Certificate Services. Microsoft's enterprise PKI. |
| **AD-Integrated DNS** | DNS zones stored as LDAP objects in the AD database, replicated by DRSR. |
| **adidnsdump** | Tool to enumerate AD-Integrated DNS via LDAP. |
| **AdminSDHolder** | AD container whose ACL is propagated by SDProp to every protected user. |
| **AES** | Advanced Encryption Standard. The Kerberos preferred cipher (AES128/AES256). |
| **APT** | Advanced Persistent Threat. Marketing term for "well-resourced attacker who stays a long time." |
| **AS-REP** | Authentication Service Reply. Second message in the Kerberos AS exchange. Contains the TGT. |
| **AS-REQ** | Authentication Service Request. First message in Kerberos AS exchange. |
| **AS-REP roast** | Offline crack of a user's password where pre-auth is disabled. |
| **ATT&CK** | MITRE's framework of attacker techniques. |
| **AV** | Antivirus. |
| **AzureAD Connect** | Sync engine between on-prem AD and Entra ID. Out of scope. |
| **BadSuccessor** | A 2024+ class of attacks abusing the dMSA / managed-account migrations. |
| **BloodHound** | Graph tool for AD attack-path analysis. CE = Community Edition, modern fork. |
| **CA** | Certificate Authority. |
| **ccache** | Credential cache. MIT-Kerberos ticket file format. |
| **Certifried** | CVE-2022-26923. Machine-account PKINIT bypass. |
| **certipy** | Python tool for ADCS abuse. |
| **CIFS** | Common Internet File System. Microsoft's name for SMB in some contexts. Sometimes shows as an SPN class. |
| **CRL** | Certificate Revocation List. |
| **DACL** | Discretionary Access Control List. The "who can do what" part of a security descriptor. |
| **DCOM** | Distributed COM. RPC-over-DCE for object-oriented IPC. |
| **DCSync** | Replicating directory secrets via DRSR from a non-DC client. |
| **DCShadow** | Pretending to be a DC and pushing arbitrary attribute changes via DRSR. |
| **DfI** | Defender for Identity. Microsoft's identity threat detection product. |
| **DFSCoerce** | Coercion via MS-DFSNM. |
| **DnsAdmins** | Built-in group; abusable via dnscmd /serverlevelplugindll. |
| **DPAPI** | Data Protection API. Per-user secret storage in Windows. |
| **DPAPI-NG** | Next-gen DPAPI used for SID-protected secrets including gMSA passwords. |
| **DRSR** | Directory Replication Service Remote protocol. The MS-DRSR specification. |
| **DSRM** | Directory Services Restore Mode. A local-admin account on every DC. |
| **EA** | Enterprise Admins. Forest-wide admin group, lives in the root domain. |
| **EDR** | Endpoint Detection and Response. |
| **EFS / EFSRPC** | Encrypting File System / its RPC interface. PetitPotam abuses this. |
| **EKU** | Extended Key Usage. Certificate OID specifying intended purpose. |
| **EPA** | Extended Protection for Authentication. NTLM channel binding. |
| **ETW** | Event Tracing for Windows. Internal logging facility. |
| **FAST** | Flexible Authentication Secure Tunneling. Kerberos armoring extension. |
| **FIM** | File Integrity Monitoring; or Forefront Identity Manager (rare). |
| **FSMO** | Flexible Single Master Operation. The five non-replicated roles in AD. |
| **GC** | Global Catalog. Subset of attributes from every domain in the forest, queryable on port 3268/3269. |
| **gMSA** | Group Managed Service Account. Auto-rotating password, password retrievable via DPAPI-NG. |
| **GPO** | Group Policy Object. Configuration container with a SYSVOL component. |
| **GPP** | Group Policy Preferences. Legacy mechanism that stored encrypted passwords in SYSVOL. |
| **Hashcat** | GPU password cracker. |
| **IFM** | Install From Media. Way to seed a DC from a backup. |
| **JEA** | Just Enough Administration. PowerShell role-based access. |
| **JIT** | Just-In-Time access. |
| **KCC** | Knowledge Consistency Checker. AD's replication topology builder. |
| **KDC** | Key Distribution Center. The Kerberos server (lives on every DC). |
| **kerbrute** | Tool for Kerberos user enumeration and password spraying. |
| **kirbi** | Microsoft Kerberos ticket file format. |
| **krbtgt** | The hidden account whose hash signs every TGT. |
| **LAPS** | Local Administrator Password Solution. Microsoft's local-admin password manager. |
| **LDAP** | Lightweight Directory Access Protocol. The AD query language. |
| **LDAPS** | LDAP over TLS. Port 636. |
| **LM** | LAN Manager. Ancient password hash. Disabled by default since 2008. |
| **LLMNR** | Link-Local Multicast Name Resolution. Broadcast DNS-like fallback. |
| **LSA** | Local Security Authority. The Windows subsystem that holds creds in memory. |
| **LSASS** | LSA Subsystem Service. The process attackers want to dump. |
| **MAQ** | MachineAccountQuota. How many computer accounts a user can create. Default 10. |
| **mDNS** | Multicast DNS. Apple's name resolution; also Windows 10+. |
| **MDI** | Microsoft Defender for Identity. See DfI. |
| **MIM** | Microsoft Identity Manager. Sync product for cross-forest identity. |
| **mimikatz** | The original Windows credential extraction tool. |
| **mitm6** | IPv6 takeover tool. |
| **MS-DRSR** | Directory Replication Service Remote spec. |
| **MS-EFSR** | Encrypting File System Remote protocol. |
| **MS-NRPC** | Netlogon Remote Protocol. ZeroLogon target. |
| **MS-PAC** | Privilege Attribute Certificate spec. |
| **MS-RPRN** | Print System Remote spec. SpoolSample target. |
| **MSSQL** | Microsoft SQL Server. |
| **NBT-NS** | NetBIOS Name Service. Legacy name resolution, also poisonable. |
| **netexec / nxc** | Modern replacement for crackmapexec. |
| **NetNTLMv1/v2** | Network NTLM authentication response, sniffable/relayable. |
| **NLA** | Network Level Authentication. RDP's pre-auth Kerberos/NTLM. |
| **noPac** | CVE-2021-42278 + CVE-2021-42287. sAMAccountName spoofing. |
| **NRPC** | Netlogon Remote Procedure Call. Used for secure-channel auth between domain members and DCs. |
| **NTAuthCertificates** | The list of CAs trusted for NT-Auth (smartcard logon). |
| **NTDS** | The AD database file. `ntds.dit`. |
| **NTLM** | Microsoft NT LAN Manager auth protocol. |
| **ntlmrelayx** | Impacket's NTLM relay tool. |
| **OPK** | One-time Password Keys. Symmetric per-session keys for Kerberos. |
| **OU** | Organizational Unit. AD container for delegation. |
| **PAC** | Privilege Attribute Certificate. Microsoft extension to Kerberos tickets carrying authz data. |
| **PAW** | Privileged Access Workstation. Hardened admin host. |
| **PetitPotam** | Coercion via MS-EFSR. |
| **PKINIT** | Public Key Cryptography for Initial Authentication. Kerberos with certs. |
| **PowerView** | PowerShell AD enumeration toolkit. |
| **PPL** | Protected Process Light. The mechanism behind LSA Protection. |
| **PRT** | Primary Refresh Token. Azure AD concept; not in scope. |
| **PSSession** | PowerShell remoting session. |
| **PtH / PTH** | Pass-the-Hash. |
| **PtK / PTK** | Pass-the-Key (AES). |
| **PtT / PTT** | Pass-the-Ticket. |
| **PtC / PTC** | Pass-the-Certificate. |
| **RBCD** | Resource-Based Constrained Delegation. |
| **RC4** | Stream cipher. The weak-but-default-historically Kerberos etype. |
| **RDP** | Remote Desktop Protocol. |
| **Responder** | Multicast poisoner + auth-capture tool. |
| **RID** | Relative Identifier. Tail end of a SID. |
| **rid-brute** | Iterating RIDs to enumerate users. |
| **RPC** | Remote Procedure Call. Microsoft's MS-RPC; or DCE/RPC depending on context. |
| **Rubeus** | C# Kerberos toolkit. |
| **S4U** | Service-for-User. Kerberos extensions S4U2Self and S4U2Proxy. |
| **SAM** | Security Account Manager. Local users database, also a registry hive. |
| **Sapphire ticket** | Variant of Diamond using S4U2Self+U2U for highest-fidelity PAC. |
| **SChannel** | The TLS SSP in Windows. |
| **SCCM** | System Center Configuration Manager. Software deployment platform. |
| **SCM** | Service Control Manager. Windows' service master. |
| **SDDL** | Security Descriptor Definition Language. ACL text format. |
| **SDProp** | SD Propagator. AD task that copies AdminSDHolder ACL to protected users. |
| **SID** | Security Identifier. |
| **Sigma** | Generic SIEM rule format. |
| **Silver ticket** | Forged TGS for one service. |
| **smbexec.py** | Impacket lateral tool using SCM. |
| **SOC** | Security Operations Center. |
| **Spooler** | Windows Print Spooler service. PrintNightmare attack surface. |
| **SPN** | Service Principal Name. Kerberos service identifier. |
| **SRV record** | DNS service record. AD publishes its services via SRV. |
| **SSP** | Security Support Provider. NTLM/Kerberos/Negotiate/Schannel are SSPs. |
| **SSPI** | Security Support Provider Interface. The Windows abstraction. |
| **Sysmon** | Sysinternals process/file/network event logger. |
| **SYSVOL** | The replicated share holding GPOs and login scripts. |
| **TGT** | Ticket-Granting Ticket. The Kerberos "session token." |
| **TGS** | Ticket-Granting Service / Service Ticket. The Kerberos per-service ticket. |
| **U2U** | User-to-User. Kerberos flag for client-to-client auth. |
| **UAC** | (1) User Account Control (Win Vista+ admin prompt); (2) userAccountControl LDAP attribute. Context-dependent. |
| **UNC** | Universal Naming Convention. `\\host\share\path`. |
| **UPN** | User Principal Name. `user@domain.com` style identifier. |
| **USN** | Update Sequence Number. AD's per-DC change counter. |
| **VBS** | Virtualization-Based Security. Hyper-V partition isolating LSA secrets. |
| **WebClient** | Windows service that adds WebDAV support; HTTP-coercion sink. |
| **WinRM** | Windows Remote Management. Microsoft's SOAP-over-HTTP remote shell. |
| **WMI** | Windows Management Instrumentation. CIM-based management interface. |
| **wsmprovhost** | The WinRM child process. |
| **ZeroLogon** | CVE-2020-1472. Netlogon AES-CFB8 IV-zero issue. |

---

## FAQ

### Q: Do I need a Windows licence to do this curriculum?

No. DVAD's deployment automation downloads Windows evaluation media; you don't need a paid licence. The eval expires after 180 days; you'll redeploy long before then.

### Q: Do I need a beefy lab box?

Recommended: 8 cores, 32 GB RAM, 200 GB disk. Minimum for the `--minimal` deploy: 4 cores, 16 GB RAM, 80 GB disk. The single-DC smoke test runs in 8 GB.

### Q: How long until I can pop a DA?

Depending on your starting knowledge: total beginner — 4 to 8 weeks of part-time study; experienced Linux/security — 2 to 4 weeks; existing pentester — 1 week.

### Q: Should I take notes?

Yes. Markdown, in `~/dvad/notes/`, structured by chapter. Don't trust your memory for AD — there are too many small details that look identical but matter (RID 519 vs 512, ACE GUID 1131f6aa vs 1131f6ad).

### Q: Should I just watch YouTube instead?

For some topics yes (e.g., a 10-minute "what is Kerberos" video before chapter 05 is a good warmup). But video is a *bad* medium for the precise details AD attacks require. You can't grep a video for "DS-Replication-Get-Changes-All." Use video to motivate; use this text + the references to actually learn.

### Q: Is DVAD the same as Hack The Box's pro labs?

No. DVAD is open-source, free, locally deployable, and intentionally vulnerable in a *taught* way — every vulnerability is documented and tied to a chapter. HTB labs are excellent but they're more "find what's exploitable" and less "learn why."

### Q: What about Game-Of-Active-Directory (GOAD)?

GOAD is fantastic — same spirit as DVAD. Once you finish this curriculum, GOAD makes a great next stop. GOAD has more flavour (cross-forest French/English themes, more hosts) but doesn't have a documented learning path attached.

### Q: How do I avoid getting bored in the early chapters?

Take a peek at chapter 11 or 14 to remind yourself what you're working towards. Skim, don't read. Then go back to chapter 03 and grind through. The boredom is real and natural; the only way through it is through.

### Q: What if a tool breaks or behaves differently?

Open `~/dvad/notes/troubleshooting.md` and start a "things that didn't work for me" log. Often the issue is: tool was updated since the curriculum was written; Python version mismatch; impacket vs impacket-tools install variant; rockyou.txt zipped vs unzipped; default config differences in your distro. The skill of debugging your own tools is the most underrated skill in offence.

### Q: Should I memorize the tool flags?

No. Memorize the *concept* and the *first 1-2 letters* of the flag (`-u`, `-p`, `-d`, `-k`, `--target`). The tool's `--help` fills in the rest. Memorizing exact flag spellings is wasted neurons; the tools change.

### Q: How do I know if I'm "done"?

You've finished the curriculum when the self-assessment in §14.15 of the capstone is all checked. Most people are not "done" after one pass; pass two and pass three on a different lab (GOAD, HTB pro labs) is normal.

### Q: I don't have a Windows VM client. Can I do everything from Linux?

Mostly yes. Impacket, certipy, BloodHound, bloodyAD, nxc, evil-winrm, hashcat — all Linux. The only places you need a Windows VM are: testing in-host enumeration (PowerView), running Rubeus / SharpHound / mimikatz natively (vs through-Linux relays), and some niche exploitation. You can do 90% of DVAD with only Linux on the attacker side.

### Q: What's the most important chapter?

Chapter 04 (Active Directory) followed by chapter 05 (Authentication). Together they're the foundation everything else depends on. If you read nothing else, read these two.

### Q: Is there a video version?

No, but the references in each chapter point to talks (BlackHat, DEF CON, Troopers, x33fcon, BSides) where the original researchers present their work. A few good ones:

- harmj0y — "Wagging the Dog" (S4U + RBCD)
- Will Schroeder + Lee Christensen — "Certified Pre-Owned" (ADCS ESC1-8)
- Sean Metcalf — "Beyond Domain Admin" series
- Benjamin Delpy — every mimikatz talk
- Charlie Bromberg — coercion family talks

### Q: How do I keep up after I finish?

Subscribe to:
- The Hacker Recipes (hackndo, the wiki).
- SpecterOps blog.
- Microsoft Security Response Center.
- Defender for Identity's release notes.
- A few research Twitter/Mastodon accounts (harmj0y, _wald0, exploitph, gentilkiwi, decoder_it, etc.)

Read every Microsoft Patch Tuesday's AD-related CVEs (third Tuesday of each month). Even just the title gives you pattern recognition.

---

## Study schedule templates

Pick whichever fits your life. These are approximate; adjust as you go.

### Template 1 — Full-time student (10 weeks)

| Week | Chapters | Hours |
|---|---|---|
| 1 | 01, 02 (start) | 14 |
| 2 | 02 (finish), 03 | 14 |
| 3 | 04 | 12 |
| 4 | 05 | 14 |
| 5 | 06 | 10 |
| 6 | 07, 08 (start) | 12 |
| 7 | 08 (finish), 09 | 12 |
| 8 | 10, 11 (start) | 14 |
| 9 | 11 (finish), 12 | 14 |
| 10 | 13, 14 | 14 |

### Template 2 — Evenings + weekends (6 months)

5-7 hours per week. One chapter every 2-3 weeks. Same total hours stretched out.

### Template 3 — Sprint (3 weeks)

Chapter per day for the first 14 days. Days 15-21 are capstone + side quests. Brutal but works for cramming.

### Template 4 — One chapter per weekend (16 weekends)

Saturday: read the chapter. Sunday: do the exercises. Monday-Friday off (decompress). Slowest but highest-retention.

---

## Common stumbling blocks

A list of things students get stuck on, with the fix.

### "BloodHound doesn't show anything"

You probably collected with insufficient privileges or pointed at the wrong DC. Re-run with `-c All` and `-ns <DC IP>`. Check the import succeeded in the BloodHound GUI (Database Info → Users count should be > 0).

### "Kerberos auth fails with 'KDC has no support for encryption type'"

The service account doesn't have AES keys, or your client requested an etype the KDC won't issue. Add `udp_preference_limit=0` to your krb5.conf and explicitly set `default_tkt_enctypes` to `rc4-hmac` if you're on RC4-only.

### "Impacket says 'Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)'"

Your attacker host's clock differs from the DC by more than 5 minutes. Sync: `sudo ntpdate -s <DC IP>` or `sudo timedatectl set-time '...'`.

### "secretsdump dies with 'STATUS_LOGON_FAILURE'"

Wrong password or the account doesn't have DCSync rights. Verify with `nxc smb <dc> -u <user> -p <pw>` first — if that fails the credential is just wrong.

### "Certipy fails on -dc-ip"

Try without `-dc-ip` (let it resolve via DNS) or use `-dc-host` instead. Some certipy versions parse `-dc-ip` strictly.

### "Responder runs but captures nothing"

DVAD's "victim user" script may not be running. Check `dc01` has the scheduled task that does the typo'd `net use`. Or just deploy mitm6 + ntlmrelayx and induce auth yourself.

### "ntlmrelayx complains about SMB signing"

The target requires SMB signing — you can't relay to it via SMB. Switch to LDAP/LDAPS (`-t ldaps://...`) or HTTP (`-t http://ca/certsrv/...`).

### "mimikatz says 'ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list'"

LSA Protection is on. You can't dump LSASS with mimikatz user-mode. Use a different host or use a vulnerable-driver bypass (PPLKiller / EDRSandblast).

### "I have DA but the flag file isn't there"

Make sure the flag file is on the *right host* per PLAN.md. Some PE-* flags are on ws01, some on file01, etc.

### "ldapdomaindump won't authenticate"

Double-check the user/password format: `corp\\alice` not `corp/alice`. Some versions are picky.

---

## Closing note

Active Directory is older than most of the people who run it now. The protocols are older than the careers of most of the people attacking them. This curriculum is a snapshot of 2026's offensive AD landscape; pieces of it will be outdated by 2028.

But the *approach* — understand the protocols at a layer below the tools, practice methodically, document obsessively, defend by building intuition for attacker behaviour — that doesn't go out of date. Build the intuition, and the next protocol shift, the next CVE, the next clever bypass will be variations on themes you already understand.

Open [01-foundations.md](01-foundations.md). Start.

```
+-------------------------+
|  Begin chapter 01 →     |
+-------------------------+
```
