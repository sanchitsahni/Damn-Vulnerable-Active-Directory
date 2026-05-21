# DVAD Walkthrough — Index

Welcome to the Damn Vulnerable Active Directory (DVAD) walkthrough. This `docs/` tree is the operator companion to `PLAN.md` (spec) and `ad-architechture.html` (visual map). It explains how to install the lab, every attack we intentionally injected, how to perform each one with real tooling, what each attack actually *means*, how to detect it, and how to prevent it in a real environment.

> **Scope reminder:** every "vulnerability" in DVAD is intentional. The lab password `DVADlab2024!`, the disabled Defender, the weakened ACLs, the rogue cert templates — they're the spec, not a bug.
> **Authorization:** only run this on a network you own. Treat the VMs as hostile.

---

## How to read this

| If you want to... | Read |
|---|---|
| Get the lab booted | [`01-setup.md`](01-setup.md) |
| Deploy on a VPS + reach over WireGuard | [`09-vps-deploy.md`](09-vps-deploy.md) |
| Land your first foothold from outside (no creds) | [`02a-initial-access.md`](02a-initial-access.md) (IA-001..050) |
| Enumerate the environment | [`02-recon.md`](02-recon.md) (REC-001..015) |
| Exhaustive enum catalog (every technique) | [`02b-enumeration.md`](02b-enumeration.md) (ENUM-001..080) |
| Look up one host (ports, RPC pipes, vulns) | [`hosts/`](hosts/) (8 per-host crib sheets) |
| Harvest credentials / hashes / tickets | [`03-credential-access.md`](03-credential-access.md) (CRED-001..065) |
| Move between hosts and forests | [`04-lateral-movement.md`](04-lateral-movement.md) (LAT-001..035) |
| Escalate privilege locally | [`05-privilege-escalation.md`](05-privilege-escalation.md) (PE-001..060) |
| Maintain access | [`06-persistence.md`](06-persistence.md) (PER-001..037) |
| Take the whole forest | [`07-forest-compromise.md`](07-forest-compromise.md) (DF-001..040) |
| See the canonical solve and wireframe diagrams | [`08-solve-path.md`](08-solve-path.md) |

Every per-ID writeup follows the same template:

```
### <ID> — <Technique>
**What it is:** plain-English description of the attack.
**Why it works here:** the specific misconfiguration we injected in DVAD.
**Tools:** the canonical attacker tools.
**Steps:** copy/paste-ready commands.
**Detection:** Event IDs, logs, Sigma rule families.
**Prevention:** the real-world fix.
```

---

## High-level attack-flow wireframe

This is the macro pattern that 80% of DVAD solves collapse into. Detail per pattern lives in `08-solve-path.md`.

```
                     ┌──────────────────────────────────┐
                     │  EXTERNAL ATTACKER (your own     │
                     │  Kali / BlackArch) on host bridge│
                     │  10.10.0.1 — zero credentials    │
                     └────────────────┬─────────────────┘
                                      │  Phase 0 — Initial Access (IA-001..050)
                                      │    nmap, anon SMB/LDAP/DNS, Kerbrute,
                                      │    AS-REP roast (no creds), Responder,
                                      │    mitm6, MSSQL public, PetitPotam,
                                      │    ZeroLogon, PrintNightmare, ProxyShell,
                                      │    EternalBlue, Log4Shell, phishing
                                      │    (macro/LNK/ISO/HTA/library-ms),
                                      │    VPN CVE, web RCE, RDP brute, USB drop,
                                      │    SCCM PXE, VLAN hop, OAuth phish
                                      ▼
                     ┌──────────────────────────────────┐
                     │  First foothold                  │
                     │  cleartext / NT hash on a user,  │
                     │  beacon on ws01 (phish/RCE/LPE), │
                     │  or DC$ hash (ZeroLogon),        │
                     │  or coerced+relayed cert         │
                     └────────────────┬─────────────────┘
                                      │
                                      ▼
                     ┌──────────────────────────────────┐
                     │  Domain User                     │
                     │  (cracked hash or sprayed pwd)   │
                     └────────────────┬─────────────────┘
                                      │
        ┌─────────────────────────────┼──────────────────────────────┐
        ▼                             ▼                              ▼
  ┌──────────────┐            ┌────────────────┐             ┌────────────────┐
  │ Kerberoast   │            │ ADCS ESC1/4/8  │             │ Coerce + Relay │
  │ -> service   │            │ -> client-auth │             │ PetitPotam /   │
  │   acct hash  │            │   cert as DA   │             │ DFSCoerce ->   │
  │ -> crack ->  │            │ -> PKINIT ->   │             │ ntlmrelayx ->  │
  │   PtH / TGS  │            │   TGT as DA    │             │ ADCS ESC8 / LDAP│
  └──────┬───────┘            └────────┬───────┘             └────────┬───────┘
         │                             │                              │
         └─────────────────────────────┼──────────────────────────────┘
                                       ▼
                     ┌──────────────────────────────────┐
                     │  Domain Admin on corp.local      │
                     │  (DCSync krbtgt + all hashes)    │
                     └────────────────┬─────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        ┌─────────────┐       ┌──────────────┐      ┌────────────────┐
        │ Golden TGT  │       │ ExtraSID via │      │ Cross-forest   │
        │ -> any user │       │ child->parent│      │ SID History    │
        │ persistent  │       │ trust (519)  │      │ -> finance/root│
        └─────────────┘       └──────────────┘      └────────────────┘
                                      │
                                      ▼
                     ┌──────────────────────────────────┐
                     │  Enterprise Admin on root.corp   │
                     └──────────────────────────────────┘
```

---

## Forest / host crib sheet

```
corp.local (10.10.0.0/21)               finance.local (10.20.0/24)     root.corp (10.30.0/24)
─────────────────────────               ──────────────────────────     ────────────────────────
dc01.corp.local      10.10.0.10  DC     dc01.finance.local 10.20.0.10  dc01.root.corp 10.30.0.10
dc01.eu.corp.local   10.10.0.11  ChildDC
ca01.corp.local      10.10.0.12  ADCS
file01.corp.local    10.10.0.13  SMB/SSH
sql01.corp.local     10.10.0.14  MSSQL
ws01.corp.local      10.10.0.100 VICTIM Workstation
```

Lab-wide password: `DVADlab2024!`. krbtgt is reset to `KrbtgtDVAD2024!`. Cross-forest trust keys reset to `TrustKey2024!`. `MachineAccountQuota=10`.

---

## Tool inventory (run from your Kali / BlackArch on the host bridge)

> `ws01.corp.local` is a **victim** workstation, not an attacker box. Tools live on your own Kali (`10.10.0.1` from inside the lab). Zero-credential initial-access vectors are in [`02a-initial-access.md`](02a-initial-access.md).

| Purpose | Tool |
|---|---|
| AD enum + BloodHound ingest | `bloodhound-python`, `SharpHound.exe`, `BloodHound CE` |
| Kerberos | `Rubeus`, `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-getTGT` |
| Credential dump | `mimikatz`, `secretsdump.py`, `lsassy`, `nanodump` |
| Relay / coercion | `ntlmrelayx.py`, `Responder`, `mitm6`, `PetitPotam.py`, `Coercer`, `dfscoerce.py`, `printerbug.py` |
| ADCS | `Certify.exe`, `Certipy`, `certutil`, `PKINITtools` |
| Lateral exec | `psexec.py`, `wmiexec.py`, `smbexec.py`, `evil-winrm`, `dcomexec.py` |
| PrivEsc local | `winPEAS`, `PrintSpoofer`, `GodPotato`, `SweetPotato`, `SharpUp`, `Watson` |
| Coerce/relay frameworks | `KrbRelayUp`, `krbrelayx`, `Coercer` |
| Cross-platform swiss army | `netexec` (formerly `crackmapexec`) |
| SCCM | `sccmhunter`, `SharpSCCM` |
| Password cracking | `hashcat`, `john` |

---

## Defensive lens

For every attack we list **Detection** (logs/Event IDs/Sigma rule families) and **Prevention** (Microsoft-recommended hardening). Use these to build your blue-team playbooks. The point of DVAD is that you can train both colors against the same lab.

---

Next: [`01-setup.md`](01-setup.md).
