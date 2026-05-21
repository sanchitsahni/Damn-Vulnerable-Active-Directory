# Damn Vulnerable Active Directory (DVAD)

A reproducible, multi-forest Windows Active Directory lab that is **intentionally misconfigured** for offensive-security training, CTFs, and red-team practice. DVAD spins up 1–8 Windows Server 2022 VMs on QEMU/KVM with the full attack-matrix surface from `PLAN.md` already wired up: Kerberoasting, AS-REP roasting, ADCS ESC1–ESC16, ACL abuse, delegation chains, ZeroLogon, noPac, Certifried, Golden/Silver/Diamond/Sapphire tickets, SID-history injection, and a long list more.

> **DVAD is the lab equivalent of [Damn Vulnerable Web App](https://github.com/digininja/DVWA) for the Windows enterprise.** Every "bug" is a feature. Do not deploy on a network you do not own.

---

## What it builds

Three forests, eight VMs, full PLAN.md attack matrix (**382 IDs**: 252 core + IA-001..050 + ENUM-001..080, across IA / REC / ENUM / CRED / LAT / PE / PER / DF categories).

```
        ┌─────────────────────────────── corp.local (10.10.0.0/21) ──────────────────────────────┐
        │                                                                                          │
        │  dc01.corp.local    ca01.corp.local    file01.corp.local   sql01.corp.local   ws01     │
        │  Primary DC + DNS   Enterprise CA       File / SMB / SSH    MSSQL Express      Attacker │
        │  10.10.0.10         10.10.0.12          10.10.0.13          10.10.0.14         10.10.0.100│
        │                                                                                          │
        │  dc01.eu.corp.local   (child domain, parent-child trust)                                 │
        │  10.10.0.11                                                                              │
        └──────────────────────────────────────────────────────────────────────────────────────────┘
                │                                       │
                │ Forest trust (External)               │ Forest trust (Tree-Root)
                ▼                                       ▼
        ┌──── finance.local ────┐               ┌──── root.corp ────┐
        │  dc01.finance.local   │               │  dc01.root.corp   │
        │  10.20.0.10           │               │  10.30.0.10       │
        └───────────────────────┘               └───────────────────┘
```

| Forest | Network | DC | Purpose |
|---|---|---|---|
| `corp.local` | `10.10.0.0/21` | `dc01.corp.local` | Primary CTF target |
| `eu.corp.local` | `10.10.0.0/21` | `dc01.eu.corp.local` | Child domain (parent-child trust) |
| `finance.local` | `10.20.0.0/24` | `dc01.finance.local` | External forest trust target |
| `root.corp` | `10.30.0.0/24` | `dc01.root.corp` | Tree-root trust target |

**Lab password (everywhere): `DVADlab2024!`** — not a secret, intentionally weak.

---

## Requirements

- Linux host with **KVM** (Intel VT-x or AMD-V enabled in BIOS)
- ~**18 GB free RAM** (full lab) / ~12 GB (minimal) / ~3 GB (single-dc)
- ~**100 GB free disk** for QCOW2 images + Windows ISO + virtio-win
- `sudo` access (bridge creation, dnsmasq, nftables rules need root)
- Internet access on first run for Windows ISO + dependency install

Distributions detected and supported by `deploy.sh`:
- Debian / Ubuntu / Linux Mint / Pop!_OS (`apt`)
- Fedora / RHEL / CentOS Stream / Rocky / AlmaLinux (`dnf`)
- Arch / Manjaro / EndeavourOS (`pacman`)
- openSUSE / SLES (`zypper`)

---

## Quick start

```bash
git clone <this-repo> DVAD
cd DVAD

# Full lab (8 VMs, ~18 GB RAM):
./deploy.sh

# Smaller deployments:
./deploy.sh --minimal      # corp.local only (5 VMs, ~12 GB)
./deploy.sh --single-dc    # one DC for a smoke test (1 VM, ~3 GB)

# Resource caps:
./deploy.sh --memory 24 --cpus 12 --disk-path /mnt/vms

# Headless VPS profile (VNC on loopback, no GUI):
./deploy.sh --vps --vnc-bind 127.0.0.1
```

`deploy.sh` runs seven phases end-to-end:

1. OS detection + dependency install (`qemu`, `libvirt`, `swtpm`, `ovmf`, `ansible`, `dnsmasq`, …)
2. Bridge + dnsmasq + nftables setup (`qemu/network/setup-network.sh`)
3. Windows Server 2022 ISO + virtio-win download into `media/`
4. Per-VM `autounattend.xml` + `post-install.ps1` generation, then VM boot (`qemu/vm-create.sh`)
5. Wait for VMs to finish Windows setup (`scripts/wait-vms.sh`)
6. Massgrave activation on each VM
7. Ansible provisioning: domain promotion, trusts, ADCS, then the full vulnerability injection matrix (`ansible/playbooks/site.yml`)

Expect **45–90 minutes** for a full first run (Windows install dominates; subsequent re-runs of Ansible alone are minutes).

---

## After deployment

```bash
# Re-run only the Ansible playbook (VMs already up):
cd ansible
ansible-playbook -i inventory.yml playbooks/site.yml -v

# Syntax / dry-run validation:
ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventory.yml playbooks/site.yml --check
```

Connect to a VM:

```bash
# VNC console (port varies per VM; see qemu/vm-create.sh VM_DEFS):
vncviewer 127.0.0.1:5901

# WinRM (Ansible uses this; ports 5985/5986 are open after post-install):
evil-winrm -i 10.10.0.10 -u Administrator -p 'DVADlab2024!'

# RDP (some VMs have RDP enabled by post-install.ps1):
xfreerdp /v:10.10.0.100 /u:Administrator /p:'DVADlab2024!'
```

Victim workstation `ws01.corp.local` (`10.10.0.100`) ships with tool path stubs (`C:\Tools\`) but **no binaries** — you don't run attacks from `ws01`. Attacks run from **your own Kali / BlackArch** on the host bridge (the box that ran `deploy.sh`). Bring your own `impacket`, `BloodHound`, `certipy`, `Rubeus`, `mimikatz`, `netexec`, `Responder`, `mitm6`, `ntlmrelayx`, etc. See [`docs/02a-initial-access.md`](docs/02a-initial-access.md) for Kali prep + zero-cred initial access vectors.

---

## Deployment flags (`./deploy.sh --help`)

| Flag | Effect |
|---|---|
| `--minimal` | Only `corp.local` (5 VMs, ~12 GB RAM) |
| `--single-dc` | Single DC smoke test (1 VM, ~3 GB RAM) |
| `--vps` | Headless VPS profile: bigger per-VM RAM, VNC on loopback only, host-capacity pre-flight, no display devices |
| `--memory GB` | Total RAM budget across all VMs (default: 18 full / 28 vps) |
| `--cpus N` | Total vCPU budget (default: 10 full / 14 vps) |
| `--disk-path PATH` | Override VM disk storage directory (default: `./vms`) |
| `--vnc-bind ADDR` | Bind VNC to `ADDR` (default `127.0.0.1`; `0.0.0.0` exposes all interfaces — only safe behind a firewall/VPN) |

---

## Repository layout

```
DVAD/
├── deploy.sh                    # Entry point (the only script you run)
├── PLAN.md                      # Authoritative attack-matrix spec (382 IDs)
├── ad-architechture.html        # Visual companion to PLAN.md
├── AGENTS.md / CLAUDE.md        # Orientation docs for AI coding agents
├── qemu/
│   ├── vm-create.sh             # VM_DEFS, libvirt-less VM lifecycle
│   ├── network/setup-network.sh # Bridges + dnsmasq + nftables NAT
│   └── ...
├── ansible/
│   ├── inventory.yml            # 8 hosts across 3 forests
│   ├── playbooks/site.yml       # Master playbook (12 phases)
│   ├── group_vars/all.yml
│   ├── tasks/
│   │   ├── ad-ds-setup.yml          # Forest root promotion
│   │   ├── child-domain-setup.yml   # eu.corp.local
│   │   ├── trust-setup.yml          # Cross-forest trusts
│   │   ├── adcs-setup.yml           # ADCS enterprise CA
│   │   ├── vuln-recon.yml           # REC-001..015
│   │   ├── vuln-cred-access.yml     # CRED-001..065
│   │   ├── vuln-lateral.yml         # LAT-* DC-side
│   │   ├── vuln-lateral-file01.yml  # LAT-* SSH pivot
│   │   ├── vuln-lateral-ws01.yml    # LAT-* SMB signing, coercion drops
│   │   ├── vuln-acl.yml             # ACL abuse vectors
│   │   ├── vuln-privesc-file.yml    # PE-* on file01
│   │   ├── vuln-privesc-sql.yml     # PE-* on sql01
│   │   ├── vuln-privesc-ws01.yml    # PE-* on ws01
│   │   ├── vuln-privesc-dc.yml      # Operators, GPO scripts
│   │   ├── vuln-persistence.yml     # PER-001..037
│   │   ├── vuln-forest-compromise.yml # DF-001..040
│   │   └── flag-deployment.yml
│   └── roles/
│       ├── windows_base/        # Defender off, WinRM on, firewall off, etc.
│       ├── ad_domain/           # OUs, users, groups, weak password policy
│       ├── adcs_vulns/          # ESC1–ESC16 templates
│       ├── network_setup/       # DNS, trusts
│       ├── vuln_setup/          # Cross-cutting vuln injection
│       └── flag_factory/        # 382-flag manifest → C:\Flags\*.txt
└── scripts/                     # wait-vms.sh, helpers
```

Phases 6–9 of `playbooks/site.yml` are the **vulnerability injection** phases — they are the whole point of the lab.

---

## What's intentionally broken

Short list (the long list is `PLAN.md` + `ad-architechture.html`):

- Defender disabled, firewall off, UAC weakened on every host
- `MachineAccountQuota = 10` (noPac/Certifried precondition)
- `krbtgt` reset to a known value (`KrbtgtDVAD2024!`) for deterministic Golden Tickets
- ADCS ESC1, ESC2, ESC3, ESC4, ESC6, ESC8, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15, ESC16 templates published
- Kerberoastable service accounts with weak passwords
- AS-REP roastable accounts (`DoNotRequirePreAuth`)
- DCSync rights granted to a non-admin (`sync_user`)
- SID filtering disabled on all cross-forest trusts; trust keys reset to `TrustKey2024!`
- `FullSecureChannelProtection = 0` (ZeroLogon precondition)
- Backup Operators / Server Operators / Print Operators / Schema Admins populated with low-priv users
- AdminSDHolder GenericAll backdoor on `user2`
- Unconstrained delegation on `svc_legacy`, gMSA backdoor, RBCD on `FILE01$`
- SMB signing not required, LDAP signing not required, LLMNR on, IPv6 enabled (mitm6)
- And ~370 more IDs — see `PLAN.md`

**Do not "fix" any of these unless you're explicitly working outside the lab spec.** If you find something that looks broken and isn't in `PLAN.md`, that is a bug; file it.

---

## Resetting / tearing down

```bash
# Destroy all VMs (qcow2 disks deleted):
bash qemu/vm-create.sh destroy

# Tear down bridges + dnsmasq + nftables rules:
bash qemu/network/setup-network.sh destroy

# Re-run cleanly:
./deploy.sh
```

The `vms/` and `media/` directories survive a destroy of bridges; remove them manually if you want to reclaim disk.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `Permission denied` on `/dev/kvm` after install | You were added to the `kvm`/`libvirt` groups but haven't re-logged in. Log out and back in. |
| Ansible WinRM connection refused | VM hasn't finished `post-install.ps1` yet. `scripts/wait-vms.sh` waits on the `vms/<name>.installed` marker; if missing, watch the VM via VNC. |
| `nltest /domain_trusts` fails after deploy | Trusts depend on DNS conditional forwarders being in place. Re-run the Ansible site playbook; it is idempotent. |
| Massgrave activation hangs | The host has no internet, or outbound to `massgrave.dev` is blocked. Activation is best-effort; you can ignore failures for short-term lab use. |
| VM kernel panics / triple-fault on boot | UEFI/OVMF firmware version mismatch — make sure `swtpm` and `ovmf` are installed from your distro's repos, not pinned to an older version. |

---

## Disclaimer

DVAD is a research and training tool. It deliberately produces a Windows AD environment that is trivially exploitable. **Do not deploy it on a network you do not control.** The authors accept no responsibility for misuse. The lab password and intentionally vulnerable configurations are public; treat the VMs as hostile.

---

## Running on a VPS (remote access via WireGuard)

The lab is happy on a VPS — you SSH in, run `./deploy.sh --vps`, and your laptop's Kali joins the lab subnets over a WireGuard tunnel. No port-forwarding individual services; the attacker peer routes the whole `10.10.0.0/21 + 10.20.0.0/24 + 10.30.0.0/24` block.

```bash
# On the VPS (≥ 24 GB RAM recommended for full lab):
./deploy.sh --vps                              # builds the lab, headless
sudo bash scripts/vps-wg-gateway.sh up         # spins up a WG server, prints client conf

# On your Kali / BlackArch laptop:
sudo wg-quick up ./dvad-attacker.conf          # paste the printed conf here
nxc smb 10.10.0.10 -u alice -p 'DVADlab2024!'  # full lab is reachable
```

See [`docs/09-vps-deploy.md`](docs/09-vps-deploy.md) for the threat-model caveats (do NOT expose the lab directly to the internet — every VM is intentionally vulnerable; the WG gateway is the only safe ingress) and the firewall rules the script applies.

---

## Documentation map

| Doc | Purpose |
|---|---|
| [`docs/00-index.md`](docs/00-index.md) | Master index — start here |
| [`docs/01-setup.md`](docs/01-setup.md) | Deployment + attacker-box prep (your own Kali) |
| [`docs/02-recon.md`](docs/02-recon.md) | Phase 1 recon |
| [`docs/02a-initial-access.md`](docs/02a-initial-access.md) | **IA-001..050** — how to land the first foothold without credentials |
| [`docs/02b-enumeration.md`](docs/02b-enumeration.md) | **ENUM-001..080** — full Windows / AD enumeration catalog |
| [`docs/hosts/`](docs/hosts/) | Per-host crib sheets (8 files: ports, RPC pipes, shares, vulns) |
| [`docs/04-lateral-movement.md`](docs/04-lateral-movement.md) | Phase 4 lateral movement |
| [`docs/08-solve-path.md`](docs/08-solve-path.md) | End-to-end solve patterns (A–N) with wireframes |
| [`docs/09-vps-deploy.md`](docs/09-vps-deploy.md) | VPS + WireGuard gateway threat model |
| `WALKTHROUGH.md` | End-to-end deploy → 25 attack paths → domain admin (canonical + cross-forest) |
| `PLAN.md` | Authoritative attack-matrix spec (every flag ID + precondition) |
| `ad-architechture.html` | Visual companion (open in a browser) |
| `AGENTS.md` / `CLAUDE.md` | Orientation docs for AI coding agents working on this repo |
