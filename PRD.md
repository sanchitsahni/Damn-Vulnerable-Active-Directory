# Product Requirements Document — DVAD (Damn Vulnerable Active Directory)

**Version:** 3.0  
**Status:** Build-ready / Active development  
**Owner:** @sanchitsahni  
**Classification:** Open-source / Research & Training only  
**Date:** 2025-05-24  

---

## 1. Executive Summary

DVAD is a **self-deploying, multi-forest Windows Active Directory CTF lab** that provisions 1–8 intentionally misconfigured VMs on QEMU/KVM via a single `./deploy.sh` command. It is the enterprise-security equivalent of DVWA: every "bug" (disabled Defender, weak service accounts, ESC-vulnerable certificate templates, unconstrained delegation, SMB1, ZeroLogon preconditions, etc.) is a deliberate training feature.

**Target users:** Red-team operators, blue-team defenders, penetration-testers, CTF organizers, and cybersecurity students who need a reproducible, full-spectrum Active Directory attack surface.

**Deployment footprint:** ~12 vCPUs, ~18 GB RAM, ~215 GB disk (thin-provisioned QCOW2 ~60 GB actual).

**Value proposition:** A single script takes a bare-metal or VPS Linux host to "domain admin on three forests" in under 90 minutes, with zero manual Windows setup.

---

## 2. Goals & Objectives

| # | Goal | Success Criteria |
|---|---|---|
| G1 | **One-command deployment** — `./deploy.sh` installs deps, builds networks, downloads Windows media, creates VMs, waits for install, activates Windows, and runs Ansible | Time to first WinRM < 90 min on a modern host |
| G2 | **Complete attack-surface coverage** — every major AD / Windows privilege-escalation technique from 2014–2025 is reachable | 382 flag IDs mapped across IA/REC/ENUM/CRED/LAT/PE/PER/DF |
| G3 | **Multi-forest realism** — parent-child, tree-root, and external trusts with SID filtering disabled | Cross-forest Golden Ticket + ExtraSID attacks work out of the box |
| G4 | **Reproducible & portable** — runs on Debian/Ubuntu/Fedora/Arch/openSUSE, bare-metal or VPS | CI-free validation via `ansible-playbook --syntax-check` and smoke pings |
| G5 | **Safe by isolation** — lab networks are L2-isolated Linux bridges; attacker is an external Kali/BlackArch box | No egress from lab→internet after install phase |
| G6 | **Educational scaffolding** — `STUDY/` curriculum + `docs/` operator walkthroughs + `WALKTHROUGH.md` copy-paste chains | A beginner can go from "never touched AD" to "Enterprise Admin" in a weekend |

---

## 3. Target Audience & Personas

| Persona | Role | Needs met by DVAD |
|---|---|---|
| **Ava — Aspiring Penetration Tester** | Self-taught, studying for OSCP/eCPPT/CRTP | Needs a safe, full-AD environment to practice Kerberoasting, DCSync, ADCS ESC chains without breaking a production domain |
| **Ben — Blue Team Analyst** | SOC analyst transitioning to threat hunting | Needs to understand how attacks manifest in Windows event logs; wants to build detection rules against known-bad behavior |
| **Casey — CTF Organizer** | Runs internal enterprise CTFs | Needs a reproducible, resettable lab with 382 flaggable challenges across difficulty tiers |
| **Dean — Red Team Lead** | Runs adversary-simulation engagements | Needs a reference environment to test tooling (C2 frameworks, BloodHound ingestors, custom scanners) before client use |
| **Erin — University Instructor** | Teaches enterprise security courses | Needs an automated lab that scales to 30 student laptops without per-station Windows licensing issues |

---

## 4. Product Scope

### 4.1 In Scope

- **Infrastructure automation** — Bash scripts for QEMU/KVM VM lifecycle, Linux bridge networking, dnsmasq DHCP, nftables NAT
- **Windows Server 2022 Core** automated install via `autounattend.xml` + `post-install.ps1`
- **Multi-forest AD topology** — `corp.local` (parent + child `eu.corp.local`), `finance.local` (external trust), `root.corp` (tree-root trust)
- **Vulnerability injection** — 382 flag IDs across 8 MITRE ATT&CK-like phases (Initial Access → Recon → Enumeration → Credential Access → Lateral Movement → Privilege Escalation → Persistence → Domain/Forest Compromise)
- **ADCS enterprise CA** with ESC1–ESC16 vulnerable certificate templates
- **Ansible-driven post-deployment** — domain promotion, trust creation, user/group provisioning, ACL abuse, delegation misconfigurations, GPO backdoors, flag placement
- **Deployment profiles** — full (8 VMs), minimal (5 VMs), single-DC (1 VM), VPS headless + WireGuard gateway
- **Documentation layers** — `STUDY/` curriculum, `docs/` operator walkthroughs, `WALKTHROUGH.md` end-to-end chains, per-host crib sheets

### 4.2 Out of Scope (for this version)

- Attacker VM / Kali image shipping — attackers bring their own tooling
- Windows desktop GUI VMs — all VMs run Server Core (reduced footprint)
- Exchange Server, SCCM, WSUS — referenced in `PLAN.md` as operator-extended; no automation
- Real-time scoring engine — flags are static files; external scoreboard is user-provided
- Automated EDR / SIEM ingestion — detection notes are documentation-only
- Cloud-native deployment (AWS/Azure) — QEMU/KVM on Linux host only

### 4.3 Future Roadmap (Post-v3.0)

- [ ] **RO-01** — Azure AD / Entra ID hybrid-join bridge (PTA/PHS/Conditional Access lab)
- [ ] **RO-02** — Exchange 2019 VM + ProxyShell/ProxyNotShell automation
- [ ] **RO-03** — SCCM/MECM lab extension (PXE, NAA, policy abuse)
- [ ] **RO-04** — Automated reset-to-snapshot for CTF rounds
- [ ] **RO-05** — Containerized attacker toolkit sidecar (optional Docker-based tooling)
- [ ] **RO-06** — Web-based scoring dashboard + flag submission API
- [ ] **RO-07** — RODC + password-replication-policy abuse surface
- [ ] **RO-08** — Linux-in-AD extension (AD-joined Ubuntu with SSSD abuse)

---

## 5. Architecture Overview

### 5.1 High-Level System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Linux Host ( bare-metal / VPS )              │
│  ./deploy.sh  ──►  7 phases end-to-end                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ dvad-ctf     │  │dvad-finance  │  │ dvad-root    │          │
│  │ 10.10.0.1/24 │  │10.20.0.1/24 │  │10.30.0.1/24 │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                  │
│    ┌────┴────┐       ┌────┴────┐       ┌────┴────┐             │
│    │ CORP    │       │FINANCE  │       │ ROOT    │             │
│    │ forest  │       │ forest  │       │ forest  │             │
│    │ 6 VMs   │       │ 1 VM    │       │ 1 VM    │             │
│    └─────────┘       └─────────┘       └─────────┘             │
│                                                                 │
│  Attacker box (Kali/BlackArch) ──► host bridge or WireGuard    │
│  Zero-cred start ──► any of IA-001..050                         │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Forest Topology

```
                              +---------------------------+
                              │   ENTERPRISE ROOT         │
                              │   Forest: ROOT.CORP       │
                              │   dc01.root.corp          │
                              +-------------+-------------+
                                            |
              +-----------------------------+-----------------------------+
              |                                                           |
+-------------v-------------+                               +-------------v-------------+
│  Forest: CORP.LOCAL       │                               │  Forest: FINANCE.LOCAL    │
│  corp.local (parent)      │                               │  dc01.finance.local       │
│  eu.corp.local (child)    │                               +-------------+-------------+
│  + ca01, file01, sql01    │                                             |
│  + ws01 (victim WS)       │                               External Trust (bi-dir)
+-------------+-------------+                                             v
                                              contractor.corp (stub / operator-extended)

Trusts:
  ROOT.CORP  <~> CORP.LOCAL   (Tree-Root,  bi-dir, SID filtering OFF)
  ROOT.CORP  <~> FINANCE.LOCAL (External,   bi-dir, SID filtering OFF)
  CORP.LOCAL parent <~> eu.corp.local child
  FINANCE.LOCAL <~> contractor.corp (One-way incoming)
```

### 5.3 VM Manifest

| Host | IP | Bridge | RAM | vCPU | VNC | Role |
|---|---|---|---|---|---|---|
| `dc01.corp.local` | `10.10.0.10` | `dvad-ctf` | 3 GB | 2 | :5901 | Primary DC, DNS, ADCS schema |
| `dc01.eu.corp.local` | `10.10.0.11` | `dvad-ctf` | 2 GB | 1 | :5902 | Child DC (ExtraSID target) |
| `ca01.corp.local` | `10.10.0.12` | `dvad-ctf` | 2 GB | 1 | :5903 | Enterprise CA (ESC1–16) |
| `file01.corp.local` | `10.10.0.13` | `dvad-ctf` | 1.5 GB | 1 | :5904 | File server, SMB1, NFS, FTP, Telnet |
| `sql01.corp.local` | `10.10.0.14` | `dvad-ctf` | 2 GB | 1 | :5905 | MSSQL (mixed-mode, xp_cmdshell) |
| `ws01.corp.local` | `10.10.0.100` | `dvad-ctf` | 3 GB | 2 | :5906 | Victim workstation (phishing landing) |
| `dc01.finance.local` | `10.20.0.10` | `dvad-finance` | 2 GB | 1 | :5907 | External trust DC |
| `dc01.root.corp` | `10.30.0.10` | `dvad-root` | 2 GB | 1 | :5908 | Tree-root trust DC |

> Invariant: Hostname/IP/MAC/bridge are hardcoded in four places that must stay in sync.

---

## 6. Functional Requirements

### 6.1 Deployment Pipeline (7 Phases)

| Phase | Script | Responsibility |
|---|---|---|
| P0 — Dependency Detect | `deploy.sh` | Auto-detect OS (apt/dnf/pacman/zypper), install qemu/libvirt/swtpm/ovmf/ansible/dnsmasq/nftables |
| P1 — Network Setup | `qemu/network/setup-network.sh` | Create dvad-ctf/finance/root bridges + dvad-nat; start dnsmasq; write nftables NAT rules |
| P2 — Media Download | `scripts/download-windows.sh` | Fetch Windows Server 2022 Eval ISO + virtio-win ISO into media/ (~5 GB, idempotent) |
| P3 — VM Create & Boot | `qemu/vm-create.sh` | Generate per-VM autounattend.xml + post-install.ps1, pack into ISO, launch QEMU VMs |
| P4 — Wait Loop | `scripts/wait-vms.sh` | Poll .installed markers; block until all VMs finish Windows setup |
| P5 — Activation | `scripts/activate-windows.sh` | Run Massgrave.dev activation per VM (best-effort) |
| P6 — Ansible Provisioning | `ansible/playbooks/site.yml` | Domain promotion → trusts → ADCS → users → vuln injection → flags → verify → handout |
| P7 — Finalize | `scripts/finalize.sh` | Sanity checks, summary output, optional snapshot creation |

### 6.2 Deployment Profiles

| Profile | VMs | RAM | vCPU | Use Case |
|---|---|---|---|---|
| full (default) | 8 | ~18 GB | 10 | Complete multi-forest CTF |
| minimal | 5 (corp only) | ~12 GB | 6 | Fast classroom/laptop demo |
| single-dc | 1 | ~3 GB | 2 | Smoke test |
| vps | 8 | ~24 GB | 14 | Headless server + WireGuard tunnel |

All profiles support `--memory`, `--cpus`, `--disk-path`, `--vnc-bind` overrides.

### 6.3 Attack Surface Matrix (382 Flag IDs)

| Phase | ID Range | Count | Representative Techniques |
|---|---|---|---|
| Initial Access | IA-001..050 | 50 | Null SMB, anon LDAP, AS-REP roast, spray, LLMNR, PetitPotam, ZeroLogon, EternalBlue, phishing |
| Reconnaissance | REC-001..015 | 15 | BloodHound, GPO enum, trust enum, ACL enum, DNS AXFR |
| Enumeration | ENUM-001..080 | 80 | RPC pipes, LDAP filters, Kerberos pre-auth, ADCS templates, SMB shares |
| Credential Access | CRED-001..065 | 65 | Kerberoast, DCSync, shadow creds, RBCD, noPac, Certifried, DPAPI, gMSA, LAPS |
| Lateral Movement | LAT-001..035 | 35 | PsExec, WMI, DCOM, WinRM, RDP PtH, cross-forest TGT, RBCD chain, ADIDNS |
| Privilege Escalation | PE-001..060 | 60 | Potato suite, SeBackup/SeImpersonate, unquoted paths, UAC bypass, Operators abuse |
| Persistence | PER-001..037 | 37 | Golden/Silver/Diamond/Sapphire tickets, skeleton key, DSRM, AdminSDHolder, GPO backdoor |
| Domain/Forest Compromise | DF-001..040 | 40 | Golden ticket, DCShadow, ExtraSID, trust ticket forge, SID-history injection, SCCM takeover |

### 6.4 Flagging System

- Each VM receives per-host `C:\Flags\FLAG-<id>-<category>.txt` files
- Flags are placed by `ansible/tasks/flag-deployment.yml`
- ACLs on flags escalate in difficulty (e.g., FLAG-IA-001 is Everyone:Read; FLAG-DF-001 requires Domain Admin)
- No automated scoring server — flags are verified by `verify-lab.yml` smoke checks

---

## 7. Non-Functional Requirements

### 7.1 Performance

| Metric | Requirement |
|---|---|
| Full deploy time (cold) | <= 90 minutes on a host with >= 18 GB RAM, SSD, gigabit internet |
| Ansible re-run time | <= 5 minutes (idempotent, skips unchanged plays) |
| VM boot time (post-install) | <= 60 seconds to WinRM ready |
| QCOW2 thin-provision efficiency | <= 60 GB actual disk for full 8-VM lab |
| Memory overhead | Host needs +4 GB above guest total for QEMU overhead + Linux buffers |

### 7.2 Reliability & Idempotency

- Re-running `./deploy.sh` must skip existing ISOs, existing QCOW2 disks, and existing bridges
- Re-running `ansible-playbook site.yml` must not duplicate users, groups, or GPOs
- `qemu/vm-create.sh destroy` + `qemu/network/setup-network.sh destroy` must return the host to pre-deploy state

### 7.3 Portability

| Host OS | Package Manager | Tested |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | apt | Primary |
| Fedora / RHEL / Rocky / AlmaLinux | dnf | Secondary |
| Arch / Manjaro / EndeavourOS | pacman | Secondary |
| openSUSE / SLES | zypper | Community |

### 7.4 Security & Isolation

- Lab VMs must have no outbound internet after install phase (NAT bridge dvad-nat is torn down)
- VNC defaults to 127.0.0.1 only; `--vnc-bind 0.0.0.0` requires explicit user opt-in with firewall warning
- WireGuard gateway (`scripts/vps-wg-gateway.sh`) is the only safe ingress for VPS deployments
- All lab passwords and keys are public (DVADlab2024!, KrbtgtDVAD2024!, TrustKey2024!) and must never be reused

### 7.5 Observability

- Per-VM logs in `vms/<name>.log`
- Ansible verbose mode (`-v`) enabled by default in `deploy.sh`
- `scripts/wait-vms.sh` prints live status of `.installed` markers
- `verify-lab.yml` smoke-checks reachability of key services (88/389/445/5985)

---

## 8. User Experience Requirements

### 8.1 First-Time User Journey

1. `git clone` the repo
2. Run `./deploy.sh`
3. Wait 45–90 min; log out/in if prompted for kvm group
4. Read the printed summary (VNC ports, connection hints)
5. Open `WALKTHROUGH.md` and execute the "Canonical 5-minute solve"
6. Validate success = NT AUTHORITY\SYSTEM on dc01.corp.local

### 8.2 Operator Iteration Loop

```bash
cd ansible
ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventory.yml playbooks/site.yml --check -v
ansible-playbook -i inventory.yml playbooks/site.yml -v
```

### 8.3 CTF Participant Journey

1. Organizer runs `./deploy.sh` and hands out docs/ + STUDY/ materials
2. Participant reads `docs/00-index.md` and sets up Kali tooling
3. Participant hunts flags in order: REC -> IA -> ENUM -> CRED -> LAT -> PE -> PER -> DF
4. Participant submits flags to external scoreboard (user-provided)

---

## 9. Dependencies & Constraints

### 9.1 External Dependencies

| Dependency | Version | Source | Purpose |
|---|---|---|---|
| Windows Server 2022 Eval ISO | Latest eval | Microsoft Eval Center (~4.9 GB) | Guest OS |
| virtio-win ISO | Latest stable | fedorapeople.org (~400 MB) | QEMU paravirtual drivers |
| Massgrave.dev script | Latest | https://massgrave.dev/get | Windows activation (best-effort) |
| Ansible | >= 2.12 | distro package / pip | Post-deployment provisioning |
| QEMU/KVM | >= 6.0 | distro package | Hypervisor |
| python3-pywinrm | >= 0.4 | pip | Ansible WinRM connection plugin |

### 9.2 Host Hardware Requirements

| Profile | RAM | vCPU | Disk | Network |
|---|---|---|---|---|
| Full | >= 22 GB free | >= 10 threads | >= 120 GB SSD | Internet on first run |
| Minimal | >= 16 GB free | >= 6 threads | >= 80 GB SSD | Internet on first run |
| Single-DC | >= 4 GB free | >= 2 threads | >= 30 GB SSD | Internet on first run |
| VPS | >= 28 GB free | >= 14 threads | >= 150 GB SSD | Internet + UDP 51820 for WG |

Mandatory: CPU virtualization extensions (vmx or svm), /dev/kvm accessible, sudo for bridge/nftables/dnsmasq.

### 9.3 Legal & Ethical Constraints

- **Not for production networks.** Every VM is trivially exploitable.
- **Do not expose to the public internet** without WireGuard tunneling.
- **Massgrave activation** is a legal gray area in some jurisdictions; it is temporary, lab-local only, and no keys are redistributed.
- **Windows Server Eval license** is 180-day; re-arm or re-deploy as needed.

---

## 10. Data Model & Configuration

### 10.1 Canonical Inventory (ansible/inventory.yml)

```yaml
all:
  children:
    corp_servers:
      hosts:
        dc01.corp.local:     { ansible_host: 10.10.0.10 }
        dc01.eu.corp.local:  { ansible_host: 10.10.0.11 }
        ca01.corp.local:     { ansible_host: 10.10.0.12 }
        file01.corp.local:   { ansible_host: 10.10.0.13 }
        sql01.corp.local:    { ansible_host: 10.10.0.14 }
    corp_workstation:
      hosts:
        ws01.corp.local:     { ansible_host: 10.10.0.100 }
    finance_dcs:
      hosts:
        dc01.finance.local:  { ansible_host: 10.20.0.10 }
    root_dcs:
      hosts:
        dc01.root.corp:      { ansible_host: 10.30.0.10 }
```

### 10.2 Key Variables (ansible/group_vars/all.yml)

| Variable | Value | Purpose |
|---|---|---|
| dvad_password | DVADlab2024! | Lab-wide admin / service account password |
| krbtgt_password | KrbtgtDVAD2024! | Deterministic krbtgt for Golden Ticket exercises |
| trust_password | TrustKey2024! | Cross-forest trust key for trust-ticket forgery |
| machine_account_quota | 10 | Enables noPac / Certifried preconditions |

### 10.3 File Layout (Repository)

```
DVAD/
|-- deploy.sh                    # Entry point
|-- PLAN.md                      # 382-ID attack-matrix spec
|-- WALKTHROUGH.md               # Copy-paste operator guide
|-- PRD.md                       # This document
|-- AGENTS.md / CLAUDE.md        # AI-agent orientation
|-- qemu/
|   |-- vm-create.sh             # VM lifecycle
|   |-- network/setup-network.sh # Bridges, dnsmasq, nftables
|-- ansible/
|   |-- inventory.yml            # Canonical 8-host inventory
|   |-- group_vars/all.yml       # Lab-wide variables
|   |-- playbooks/site.yml       # Master playbook (26 plays)
|   |-- tasks/                   # Imperative AD setup + vuln injection
|   |-- roles/                   # Reusable bundles
|-- scripts/                     # Orchestration helpers
|-- docs/                        # Operator walkthroughs
|-- STUDY/                       # 14-chapter curriculum
|-- windows/autounattend/        # Base unattend template
|-- media/                       # ISOs (~5 GB, gitignored)
|-- vms/                         # QCOW2 disks (gitignored)
|-- autounattend/                # Per-VM generated output (gitignored)
```

---

## 11. Open Issues & Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Microsoft changes eval ISO URL / checksum | Medium | High | Mirror fallback; script allows manual media/ pre-placement |
| R2 | Massgrave.dev blocked or taken down | Medium | Medium | Best-effort; lab works unactivated for 180 days |
| R3 | KVM group changes require re-login | High | Low | deploy.sh warns; documented in README/Troubleshooting |
| R4 | PLAN.md and code drift over time | Medium | High | PR rule: any new flag ID must update PLAN.md first |
| R5 | Host OOM during full deploy | Medium | High | Pre-flight memory check + --memory / --minimal escapes |
| R6 | Ansible WinRM timeouts on slow hosts | Medium | Low | wait-vms.sh blocks; ansible.timeout increased |
| R7 | UEFI/OVMF version mismatch | Low | High | swtpm + ovmf from distro repos, not pinned |

---

## 12. Success Metrics & Definition of Done

A release is considered **ready** when:

1. [ ] `./deploy.sh --single-dc` completes without error in < 20 min
2. [ ] `./deploy.sh --minimal` completes without error in < 45 min
3. [ ] `./deploy.sh` (full) completes without error in < 90 min
4. [ ] `ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check` passes
5. [ ] The canonical 5-minute solve (password spray -> Kerberoast -> ESC1 -> DCSync -> Golden Ticket) succeeds
6. [ ] At least one cross-forest pattern (Pattern Q or R from WALKTHROUGH.md) succeeds
7. [ ] `nxc smb 10.10.0.0/24 -u alice -p 'DVADlab2024!'` returns all 6 corp hosts
8. [ ] docs/09-vps-deploy.md WireGuard tunnel recipe works on a fresh VPS
9. [ ] All 382 flag IDs in PLAN.md have corresponding placement logic
10. [ ] STUDY/ chapters 01-14 have no broken internal links

---

## 13. Appendix A: Glossary

| Term | Definition |
|---|---|
| ADCS | Active Directory Certificate Services |
| AS-REP | Authentication Service Response (Kerberos pre-auth reply) |
| DCSync | Replication of AD directory data via DRSGetNCChanges |
| ESC1-ESC16 | Certificate template misconfiguration classes per SpecterOps |
| ExtraSID | Injecting a foreign SID into a Kerberos PAC across trusts |
| Golden Ticket | Forged TGT signed with the krbtgt hash |
| Kerberoast | Offline cracking of service-account TGS tickets |
| LLMNR | Link-Local Multicast Name Resolution |
| noPac | SAMAccountName spoofing + Silver Ticket (CVE-2021-42278/42287) |
| PetitPotam | MS-EFSRPC coercion forcing target to auth to attacker |
| RBCD | Resource-Based Constrained Delegation |
| ZeroLogon | Netlogon empty-machine-password (CVE-2020-1472) |

---

## 14. Appendix B: MITRE ATT&CK Mapping (Summary)

| DVAD Phase | ATT&CK Tactic | Representative Techniques |
|---|---|---|
| IA (Initial Access) | TA0001 | T1078, T1133, T1566, T1190 |
| REC (Recon) | TA0043 | T1083, T1087, T1018 |
| ENUM | TA0007 | T1016, T1087, T1482 |
| CRED | TA0006 | T1003, T1550, T1558 |
| LAT | TA0008 | T1021, T1550, T1210 |
| PE | TA0004 | T1055, T1078, T1134 |
| PER | TA0003 | T1547, T1550, T1098 |
| DF | TA0005 / TA0040 | T1558, T1550, T1482, T1098 |

---

*End of PRD*
