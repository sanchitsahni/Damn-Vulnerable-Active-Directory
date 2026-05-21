# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` in the repo root is the authoritative orientation doc for any agent working here — read it first. The notes below highlight the points most often missed and the few CLAUDE-specific things AGENTS.md does not cover.

## What this repo is

DVAD = **Deployable Vulnerable Active Directory** lab. It is not application code — it is infrastructure automation (Bash + Ansible + QEMU/KVM) that builds a multi-forest Windows AD environment and **intentionally misconfigures it** for CTF/red-team practice. The "bugs" (disabled Defender, weak service accounts, ESC-vulnerable cert templates, DoNotRequirePreAuth, permissive ACLs, SMB1, etc.) are the spec, not regressions. Do not "fix" them unless explicitly asked. `PLAN.md` is the attack-vector spec; `ad-architechture.html` is the visual companion.

## Entry point and stale duplicates

- **Real entrypoint:** `./deploy.sh` at repo root. It runs 7 phases: deps → networks → Windows media → VM create → wait → Massgrave activation → Ansible. Sets `DVAD_HOME` for everything downstream.
- **Stale duplicates — do not edit:** `scripts/deploy.sh` and `qemu/vm_defs/vm-create.sh` are leftovers from an earlier iteration. Edit the root `deploy.sh` and `qemu/vm-create.sh` instead. Treat the duplicates as deletion candidates if asked to clean up.
- `.nanocoder/` is leftover tool state, **not** project config. `.nanocoder/tasks.json` is unreliable — many `in_progress` items are already done in code.

## Topology consistency (four-way invariant)

Hostnames, IPs, and MACs are hardcoded across **four** files that must stay in sync. The full table is in AGENTS.md (three forests: `corp.local` on `dvad-ctf`, `finance.local` on `dvad-finance`, `root.corp` on `dvad-root`). When adding/renaming a VM, update all four:

1. `qemu/vm-create.sh` — `VM_DEFS` associative array
2. `qemu/network/setup-network.sh` — `add_static_leases` (dnsmasq static leases)
3. `ansible/inventory.yml` — host entry **and** the right child group (`corp_servers`, `corp_workstation`, `all_dcs`, `member_servers` — `site.yml` references these by name)
4. Any role/task referencing the hostname

Lab-wide password is `DVADlab2024!` (in `ansible/inventory.yml` and `qemu/vm-create.sh`). Not a secret — intentionally vulnerable lab.

## Common commands

```bash
./deploy.sh                          # full lab (8 VMs, ~18GB RAM)
./deploy.sh --minimal                # corp.local only (5 VMs)
./deploy.sh --single-dc              # 1 VM smoke test
./deploy.sh --memory 24 --disk-path /mnt/vms

# Re-run only Ansible after VMs are up (note: inventory.yml at ansible/ root, NOT inventory/hosts.yml):
cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml -v

# Syntax / dry-run checks (closest thing to a "test"):
ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventory.yml playbooks/site.yml --check

# Tear down:
bash qemu/vm-create.sh destroy
bash qemu/network/setup-network.sh destroy
```

**No test suite, no linter, no formatter, no CI exists.** Validation is "run it and watch it boot." Don't claim a change is verified unless it has actually been booted, or syntax-checked for Ansible.

## Architecture in one screen

- `qemu/vm-create.sh` defines each VM (RAM, CPU, MAC, VNC port, bridge), generates a per-VM `autounattend.xml` + `post-install.ps1`, and packs them into a small ISO injected alongside the Windows install media. Per-VM state lives in `vms/<name>.{pid,mon,log,installed}`. The `.installed` marker is what switches `launch_vm` from install-mode (with ISOs attached) to boot-mode.
- `qemu/network/setup-network.sh` creates Linux bridges + a project-local dnsmasq under `/tmp/dvad-dnsmasq/` with static leases keyed off the MACs in `vm-create.sh`.
- `ansible/playbooks/site.yml` is the master playbook. It deliberately mixes `import_tasks: tasks/<name>.yml` (imperative AD setup) and `import_role: <name>` (vulnerability injection). Both styles are intentional. **Phases 6–9 are the vulnerability injection phases — they are the whole point of the lab.**
- Ansible connection is **WinRM/NTLM on 5985 (HTTP, cert validation off)**. Targets must have finished `post-install.ps1` (which enables WinRM and disables the firewall) before any play succeeds; `scripts/wait-vms.sh` waits on the `.installed` marker.

## Host setup gotchas

- KVM + libvirt + `swtpm` + OVMF required. `deploy.sh` installs these per distro (apt/dnf/pacman/zypper).
- User is added to `kvm` and `libvirt` groups by the script — but a **logout/login is required** before the same shell can launch VMs without sudo on `/dev/kvm`.
- Bridge creation, dnsmasq, nftables/iptables rules **require sudo**; the script calls `sudo` directly rather than running as root.
- Windows ISO + virtio-win ISO land in `media/` (~5GB). Re-runs are idempotent; existing ISOs are skipped.
- Default VM disk path is `./vms` unless `--disk-path` is passed. (The duplicate `qemu/vm_defs/vm-create.sh` uses `/var/lib/libvirt/images/ad-ctf` — another reason to ignore it.)

## Editing conventions

- All Bash scripts use `set -euo pipefail` and `IFS=$'\n\t'` — preserve that.
- `log` / `warn` / `info` / `err` helpers are redefined per script — keep them as-is rather than refactoring into a shared lib.
- Never commit anything under `media/`, `vms/`, `autounattend/<vm>/` (generated), or `/tmp/dvad-*`.
- When `PLAN.md` and code disagree, `PLAN.md` is design intent but the code is what runs. Reconcile by updating whichever the user is asking about and flag the drift.
