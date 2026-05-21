# AGENTS.md

DVAD = **Deployable Vulnerable Active Directory** lab. A multi-forest Windows AD CTF environment provisioned with QEMU/KVM + Ansible on a Linux host. There is no app/codebase — this repo is **infrastructure automation that builds Windows VMs and intentionally misconfigures them**.

## Repo shape

- `deploy.sh` (root) — **the real entrypoint**. Orchestrates 7 phases: deps → networks → Windows media → VM create → wait → Massgrave activation → Ansible. Sets `DVAD_HOME` for everything downstream.
- `scripts/deploy.sh` and `qemu/vm_defs/vm-create.sh` are **stale duplicates** from an earlier iteration. Do not edit them when fixing logic; edit the root `deploy.sh` and `qemu/vm-create.sh`. If asked to clean up, treat these as deletion candidates.
- `qemu/vm-create.sh` — VM definitions (RAM, CPU, MAC, VNC port, bridge) live in the `VM_DEFS` associative array; also generates per-VM `autounattend.xml` + `post-install.ps1` and packs them into a small ISO injected alongside the install media.
- `qemu/network/setup-network.sh` — creates Linux bridges `dvad-ctf` / `dvad-finance` / `dvad-root` + `dvad-nat`, starts a project-local dnsmasq from `/tmp/dvad-dnsmasq/`, and writes static DHCP leases keyed by the MACs in `vm-create.sh`. MACs and IPs **must stay in sync** with `ansible/inventory.yml` and the dnsmasq static leases.
- `ansible/` — runs from a Linux control node over WinRM/NTLM. `playbooks/site.yml` is the master playbook; it imports both `tasks/*.yml` files and `roles/*`. The deploy script invokes it as `ansible-playbook -i inventory.yml playbooks/site.yml -v` (note: `inventory.yml` at the ansible root, not `inventory/hosts.yml`).
- `PLAN.md` — authoritative attack-vector matrix and topology design. Treat it as the spec. `ad-architechture.html` (yes, that typo) is the visual companion referenced by PLAN.md.
- `.nanocoder/` — leftover from the Nanocoder tool, **not** OpenCode config. Ignore `.nanocoder/tasks.json` for current state; many of its `in_progress` items are already done in code.

## Topology that must stay consistent across files

Three forests, hardcoded everywhere:

| Host | IP | Bridge | MAC suffix |
|---|---|---|---|
| dc01.corp.local | 10.10.0.10 | dvad-ctf | 01:01 |
| dc01.eu.corp.local | 10.10.0.11 | dvad-ctf | 01:02 |
| ca01.corp.local | 10.10.0.12 | dvad-ctf | 01:03 |
| file01.corp.local | 10.10.0.13 | dvad-ctf | 01:04 |
| sql01.corp.local | 10.10.0.14 | dvad-ctf | 01:05 |
| ws01.corp.local | 10.10.0.100 | dvad-ctf | 01:06 |
| dc01.finance.local | 10.20.0.10 | dvad-finance | 02:01 |
| dc01.root.corp | 10.30.0.10 | dvad-root | 03:01 |

If you add/rename a VM, update **all four** sources: `qemu/vm-create.sh` `VM_DEFS`, `qemu/network/setup-network.sh` `add_static_leases`, `ansible/inventory.yml`, and any role/task that references the hostname.

Lab-wide password (Administrator, safe-mode, etc.): `DVADlab2024!`. Lives in `ansible/inventory.yml` and `qemu/vm-create.sh`. Not a secret — this is an intentionally vulnerable lab.

## Commands

```bash
./deploy.sh                          # full lab (8 VMs, ~18GB RAM)
./deploy.sh --minimal                # corp.local only (5 VMs)
./deploy.sh --single-dc              # 1 VM for smoke test
./deploy.sh --memory 24 --disk-path /mnt/vms

# Re-run only Ansible after VMs are up:
cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml -v

# Tear down VMs / networks:
bash qemu/vm-create.sh destroy
bash qemu/network/setup-network.sh destroy
```

There is **no test suite, no linter, no formatter, no CI**. Validation is "run it and watch it boot". For Ansible changes, the closest thing to a check is `ansible-playbook --syntax-check` and `--check` mode.

## Host requirements (non-obvious)

- KVM + libvirt + `swtpm` + OVMF. `deploy.sh` installs these per distro (apt/dnf/pacman/zypper).
- User must be in `kvm` and `libvirt` groups — `deploy.sh` adds them but a **logout/login is required** before the same shell can launch VMs without sudo for `/dev/kvm`.
- Bridge creation, dnsmasq, and nftables/iptables rules **require sudo**; the script calls `sudo` directly rather than running as root.
- Windows ISO and virtio-win ISO are downloaded into `media/` (~5GB). Re-runs are idempotent — existing ISOs are skipped.
- Per-VM state lives in `vms/<name>.{pid,mon,log,installed}`. The `.installed` marker switches `launch_vm` from install-mode (with ISOs attached) to boot-mode.
- Default VM disk path is `./vms` unless `--disk-path` is passed. The duplicate `qemu/vm_defs/vm-create.sh` defaults to `/var/lib/libvirt/images/ad-ctf` — another reason to ignore it.

## Ansible quirks

- Connection is **WinRM/NTLM on 5985 (HTTP, cert validation off)**. Targets must have finished `post-install.ps1` (which enables WinRM and disables the firewall) before any play will succeed — that is what `scripts/wait-vms.sh` waits for via the `.installed` marker.
- `site.yml` mixes `import_tasks: tasks/<name>.yml` and `import_role: <name>`. Both styles are intentional; the `tasks/` files do imperative AD setup, the roles inject vulnerabilities.
- Groups referenced by `site.yml` (`corp_servers`, `corp_workstation`, `all_dcs`, `member_servers`) are defined in `inventory.yml`. Adding a new host means adding it to the right child group, not just listing it under `all`.
- Phases 6–9 are the **vulnerability injection** phases. They are the whole point of the lab — do not "fix" things like `DoNotRequirePreAuth`, weak service-account passwords, overly permissive ACLs, ESC-vulnerable cert templates, SMB1, disabled Defender, etc. They are the spec, cross-referenced in `PLAN.md`.

## Editing rules of thumb

- Bash scripts use `set -euo pipefail` and `IFS=$'\n\t'`; preserve that. Logging helpers `log/warn/info/err` are redefined per script — keep them.
- The repo intentionally disables Defender, the firewall, UAC, LAPS-style protections, etc. in `post-install.ps1` and the Ansible vuln roles. Security "improvements" are out of scope unless the user explicitly asks.
- When PLAN.md and code disagree, PLAN.md is the design intent but code is what runs. Reconcile by updating whichever the user is asking about, and flag the drift.
- Do not commit anything under `media/`, `vms/`, `autounattend/<vm>/` (generated), or `/tmp/dvad-*` paths.
