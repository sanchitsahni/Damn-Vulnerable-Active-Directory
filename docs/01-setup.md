# 01 — Setup, Install, Run

This page takes you from "empty Linux box" to "lab is up, you have a domain user on `ws01`, you can start attacking." Everything here is automated by `./deploy.sh` at the repo root, but the manual walkthrough is here for when something breaks at 2am.

> Source of truth: `deploy.sh`, `qemu/vm-create.sh`, `qemu/network/setup-network.sh`, `ansible/playbooks/site.yml`.
> Stale duplicates — **do not edit:** `scripts/deploy.sh`, `qemu/vm_defs/vm-create.sh`.

---

## 1. Prerequisites

### 1.1 Hardware

| Profile | RAM | CPU | Disk | Notes |
|---|---|---|---|---|
| `--single-dc` | ~3 GB | 2 vCPU | 40 GB | smoke test only |
| `--minimal`   | ~12 GB | 6 vCPU | 80 GB | corp.local forest only (5 VMs) |
| `--full`      | ~18 GB | 10 vCPU | 100 GB | all 3 forests (8 VMs) |
| `--vps`       | ~28 GB | 14 vCPU | 120 GB | bigger per-VM RAM, headless, VNC on loopback |

KVM (Intel VT-x / AMD-V) **must be enabled in BIOS/UEFI**. Verify:

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # must be > 0
ls /dev/kvm                          # must exist
```

### 1.2 Software (auto-installed by `deploy.sh`)

`deploy.sh` detects your distro and uses the right package manager (`apt`/`dnf`/`pacman`/`zypper`). It installs:

- `qemu-system-x86`, `qemu-utils`
- `libvirt`, `virt-install`, `bridge-utils`
- `swtpm`, `ovmf` (UEFI firmware + virtual TPM — Windows 11/Server 2022 require both)
- `ansible`, `python3-winrm`, `python3-pywinrm`, `python3-requests-ntlm`
- `dnsmasq`, `iptables`/`nftables`
- `wget`/`curl`/`aria2`

If you want to inspect what's being touched: `deploy.sh` lines beginning with the `install_deps_*` functions.

### 1.3 Group membership

The script adds your user to `kvm` and `libvirt`. **You must log out and back in** before the same shell can talk to `/dev/kvm` without sudo:

```bash
sudo usermod -aG kvm,libvirt $USER
# log out completely (not just close terminal), log back in
id   # confirm kvm + libvirt show up
```

---

## 2. The deploy

```bash
git clone <this-repo> DVAD
cd DVAD
./deploy.sh                 # full lab
./deploy.sh --minimal       # corp.local only
./deploy.sh --single-dc     # one DC smoke test
./deploy.sh --memory 24 --cpus 12 --disk-path /mnt/vms
./deploy.sh --vps --vnc-bind 127.0.0.1
```

Expected runtime first time: **45–90 minutes**, dominated by Windows install. Subsequent re-runs of Ansible alone take ~5 minutes.

### 2.1 The seven phases

`deploy.sh` runs the phases below in order. Each is idempotent — you can ^C and re-run.

1. **OS detect + deps.** `setup_deps_*` for your distro. Installs everything from §1.2.
2. **Bridge + dnsmasq + nftables.** `qemu/network/setup-network.sh`. Creates `virbr1` (10.10.0.0/21, corp), `virbr2` (10.20.0.0/24, finance), `virbr3` (10.30.0.0/24, root). Spawns a project-local dnsmasq in `/tmp/dvad-dnsmasq/` with static leases keyed off the MACs in `qemu/vm-create.sh`. NAT rules are written via nftables (or iptables on older distros).
3. **Windows media download.** `media/` gets the Server 2022 Eval ISO (~4.9 GB) and the virtio-win ISO (~400 MB). Re-runs are skipped if already present. SHA256 is verified.
4. **VM create.** `qemu/vm-create.sh` per the `VM_DEFS` associative array. For each VM it:
   - generates a per-VM `autounattend.xml` and `post-install.ps1`
   - packs them onto a tiny ISO
   - launches the VM with the Windows ISO + virtio ISO + autounattend ISO attached
   - state lives in `vms/<name>.{pid,mon,log,installed}`
5. **Wait.** `scripts/wait-vms.sh` polls the `vms/<name>.installed` marker (written at the end of `post-install.ps1`). The marker is what flips `launch_vm` from install-mode to boot-mode on the next start.
6. **Massgrave activation.** Per-VM PowerShell one-liner runs `iwr massgrave.dev/get | iex`. Best-effort — if the host has no internet the lab still works for ~180 days on eval.
7. **Ansible.** `cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml -v`. This is the big one — see §4.

### 2.2 What lives where after deploy

```
DVAD/
├── deploy.sh                        # entry point
├── media/<iso files>                # Windows + virtio (~5 GB total)
├── vms/<name>.{qcow2,pid,mon,log,installed}
├── /tmp/dvad-dnsmasq/<leases,pid,conf>
├── qemu/vm-create.sh                # VM_DEFS source of truth
├── qemu/network/setup-network.sh    # bridge + dnsmasq
└── ansible/                         # post-boot config + vuln injection
```

---

## 3. Verifying the lab

### 3.1 Are the VMs up?

```bash
bash qemu/vm-create.sh status        # tabular summary
ls vms/*.installed                   # one per VM that finished post-install
ss -ltn | grep 590                   # VNC ports per VM (5900-5907)
```

### 3.2 Are the bridges + dnsmasq up?

```bash
ip -br link show virbr1 virbr2 virbr3
ps -ef | grep dnsmasq | grep dvad
cat /tmp/dvad-dnsmasq/leases         # current DHCP leases
```

### 3.3 Can you reach a VM?

```bash
ping -c 2 10.10.0.10                 # dc01.corp.local
nc -zv 10.10.0.10 5985               # WinRM
nc -zv 10.10.0.10 88                 # Kerberos
nc -zv 10.10.0.12 80                 # ADCS web enrollment
```

### 3.4 Can Ansible authenticate?

```bash
cd ansible
ansible all -i inventory.yml -m win_ping
# every host should return SUCCESS / pong
```

If a host returns `kerberos|ntlm|connection refused`, the VM hasn't finished `post-install.ps1`. Watch via VNC:

```bash
vncviewer 127.0.0.1:5900     # dc01
vncviewer 127.0.0.1:5907     # ws01 — see qemu/vm-create.sh VM_DEFS for port map
```

### 3.5 Did vulnerability injection complete?

```bash
cd ansible
ansible-playbook -i inventory.yml playbooks/site.yml --check
# zero "changed" tasks means it's converged
```

Flag files land on disk at `C:\Flags\<id>.txt` on the host that's the natural target for that ID. The flag-factory role (`ansible/roles/flag_factory/`) generates them deterministically.

---

## 4. The Ansible playbook (vuln injection)

`ansible/playbooks/site.yml` is 12 phases. Phases **6–9 are the whole point** — that's where the lab gets its teeth.

| Phase | File | What it does |
|---|---|---|
| 1 | `roles/windows_base` | Defender off, firewall off, UAC weakened, WinRM hardened-but-on |
| 2 | `tasks/ad-ds-setup.yml` | Promote `dc01.corp.local` to forest root |
| 3 | `tasks/child-domain-setup.yml` | Promote `dc01.eu.corp.local` as parent-child |
| 4 | `tasks/root-domain-setup.yml`, `tasks/finance-domain-setup.yml` | Promote root.corp + finance.local |
| 5 | `tasks/trust-setup.yml` | Cross-forest + tree-root trusts, **SID filtering disabled**, trust keys reset |
| 6 | `tasks/adcs-setup.yml` + `roles/adcs_vulns` | Enterprise CA + ESC1/2/3/4/6/8/9/10/11/13/14/15/16 templates |
| 7 | `tasks/vuln-recon.yml`, `vuln-cred-access.yml`, `vuln-kerberos.yml`, `vuln-adcs-esc.yml` | REC + CRED injection |
| 8 | `vuln-lateral.yml`, `vuln-lateral-file01.yml`, `vuln-lateral-ws01.yml`, `vuln-acl.yml`, `vuln-privesc-*.yml` | LAT + PE injection |
| 9 | `vuln-persistence.yml`, `vuln-forest-compromise.yml`, `vuln-attacker-host.yml` | PER + DF injection |
| 10 | `tasks/flag-deployment.yml` + `roles/flag_factory` | Drop `C:\Flags\*.txt` per host |
| 11 | `tasks/verify-lab.yml` | Sanity test |
| 12 | `tasks/generate-handout.yml` | Build the participant handout |

Re-run just Ansible (VMs already up):

```bash
cd ansible
ansible-playbook -i inventory.yml playbooks/site.yml -v
ansible-playbook -i inventory.yml playbooks/site.yml --tags "vuln-cred"   # subset
```

Syntax check / dry-run (the closest thing to a test suite):

```bash
ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventory.yml playbooks/site.yml --check
```

> **Inventory path:** `ansible/inventory.yml` (NOT `ansible/inventory/hosts.yml`). The latter does not exist; references to it in any stale doc are wrong.

---

## 5. Accessing the lab

### 5.1 VNC consoles

VNC ports are assigned per VM in `qemu/vm-create.sh` (`vnc_port` field). Default mapping:

| VM | VNC |
|---|---|
| dc01.corp.local | 127.0.0.1:5900 |
| dc01.eu.corp.local | 127.0.0.1:5901 |
| ca01.corp.local | 127.0.0.1:5902 |
| file01.corp.local | 127.0.0.1:5903 |
| sql01.corp.local | 127.0.0.1:5904 |
| ws01.corp.local | 127.0.0.1:5905 |
| dc01.finance.local | 127.0.0.1:5906 |
| dc01.root.corp | 127.0.0.1:5907 |

```bash
vncviewer 127.0.0.1:5905
```

### 5.2 WinRM (preferred for non-interactive)

```bash
evil-winrm -i 10.10.0.10  -u Administrator -p 'DVADlab2024!'
evil-winrm -i 10.10.0.100 -u 'corp\alice'  -p 'DVADlab2024!'
```

### 5.3 RDP

`post-install.ps1` enables RDP on each VM. Connect from your host:

```bash
xfreerdp /v:10.10.0.100 /u:Administrator /p:'DVADlab2024!' /size:1600x900 +clipboard
```

### 5.4 Username / password set

| Account | Password | Where |
|---|---|---|
| `Administrator` | `DVADlab2024!` | every VM |
| `corp\alice` (Domain User) | `DVADlab2024!` | corp.local |
| `corp\svc_web` (Kerberoastable) | `Summer2023!` | corp.local |
| `corp\svc_nopreauth` (AS-REP roastable) | `DVADlab2024!` | corp.local |
| `corp\sync_user` (DCSync rights) | `DVADlab2024!` | corp.local |
| `corp\backup_user` (Backup Operators, reversible pwd) | `DVADlab2024!` | corp.local |
| `krbtgt` | `KrbtgtDVAD2024!` | corp.local (reset for deterministic Golden) |
| trust key | `TrustKey2024!` | every cross-forest trust |

> The full account inventory is generated by `ansible/roles/ad_domain/`. Run `Get-ADUser -Filter *` on `dc01.corp.local` after deploy to enumerate.

---

## 6. Attacker box prep (your own Kali / BlackArch — *not* a lab VM)

The attacker in DVAD is **your own Kali or BlackArch host** sitting on the bridge that `deploy.sh` creates. From inside the lab you are reachable at `10.10.0.1` (and `10.20.0.1`, `10.30.0.1` for the other forests). You have full L3 to every VM. **No tools live on the lab VMs** — `ws01.corp.local` is a *victim* workstation that you'll land on later via phishing / coercion / LPE.

### 6.1 One-time Kali install

```bash
sudo apt update && sudo apt install -y \
    impacket-scripts python3-impacket bloodhound.py \
    crackmapexec netexec responder mitm6 \
    kerbrute hashcat john \
    enum4linux-ng smbmap evil-winrm proxychains4 \
    certipy-ad coercer
pipx install bloodyAD
# Rubeus / mimikatz / Certify / SharpHound — drop the .exe in ~/loot/win
```

### 6.2 /etc/hosts

```
10.10.0.10  dc01.corp.local       corp.local
10.10.0.11  ca01.corp.local
10.10.0.12  file01.corp.local
10.10.0.13  sql01.corp.local
10.10.0.100 ws01.corp.local
10.20.0.10  dc01.finance.local    finance.local
10.30.0.10  dc01.root.corp        root.corp
10.10.1.10  dc01.eu.corp.local    eu.corp.local
```

### 6.3 /etc/krb5.conf (multi-realm)

```
[libdefaults]
  default_realm = CORP.LOCAL
  dns_lookup_kdc = true
  dns_lookup_realm = true

[realms]
  CORP.LOCAL       = { kdc = dc01.corp.local }
  EU.CORP.LOCAL    = { kdc = dc01.eu.corp.local }
  FINANCE.LOCAL    = { kdc = dc01.finance.local }
  ROOT.CORP        = { kdc = dc01.root.corp }
```

### 6.4 Verify reach

```bash
nxc smb 10.10.0.0/21               # list responding hosts
nxc smb 10.10.0.10 -u '' -p ''     # null bind smoke test
kinit alice@CORP.LOCAL             # once you have a credential
```

### 6.5 If you do drop tools on `ws01` (after you've landed there)

`ws01` has stub directories under `C:\Tools\` but no binaries. Upload via SMB, evil-winrm, or your C2 once you have local admin:

```
C:\Tools\
  ├── Rubeus.exe
  ├── mimikatz.exe
  ├── SharpHound.exe
  ├── Certify.exe
  ├── PrintSpoofer.exe
  ├── GodPotato.exe
  └── winPEAS.exe
```

This is for *post-exploitation* (Kerberos token games, LSASS dumps, on-host LPE). Recon and the whole initial-access phase stay on Kali.

### 6.6 BloodHound ingest (from Kali, after first credential)

```bash
bloodhound-python -u alice -p 'DVADlab2024!' -d corp.local -ns 10.10.0.10 -c all
# upload .json files into BloodHound CE
```

---

## 7. Reset / teardown

```bash
bash qemu/vm-create.sh destroy                  # delete VM disks
bash qemu/network/setup-network.sh destroy      # tear down bridges + dnsmasq + nft rules
rm -rf vms media                                # full reclaim (loses ISOs too — careful)
./deploy.sh                                     # rebuild from scratch
```

QCOW2 disks live under `./vms/` by default (or `--disk-path`). The `vms/` and `media/` directories are not touched by `destroy` — remove them manually if you want the disk back.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Permission denied` on `/dev/kvm` | You were added to `kvm`/`libvirt` but didn't re-login. Log out completely, log back in. |
| Ansible WinRM connection refused | VM hasn't finished `post-install.ps1`. `scripts/wait-vms.sh` waits for `vms/<name>.installed`. If absent, watch via VNC. |
| `nltest /domain_trusts` empty after deploy | DNS conditional forwarders not in place. Re-run `ansible-playbook -i inventory.yml playbooks/site.yml --tags trust` (idempotent). |
| Massgrave activation hangs | Host has no internet, or outbound to `massgrave.dev` is blocked. Activation is best-effort; ignore for short-term use. |
| Windows triple-faults on boot | OVMF/swtpm version mismatch. Reinstall from your distro's stable repo. |
| `dnsmasq: failed to bind DHCP server socket` | Another dnsmasq is running. `sudo systemctl stop dnsmasq` (system one); the project uses its own in `/tmp/dvad-dnsmasq/`. |
| ISO download stalls | Microsoft eval CDN occasionally throttles. Re-run; aria2c resumes. |
| `qemu-system-x86_64: Could not open ovmf code` | `ovmf` not installed. `sudo apt install ovmf` (or equivalent). |
| BloodHound ingest "Could not connect" | DNS lookup on the DC failed. Pass `-ns 10.10.0.10` explicitly. |
| `kerberos: server not found in Kerberos database` | Your client clock skew > 5 min from the DC. `sudo chronyc -a 'makestep'` or `ntpdate 10.10.0.10`. |

---

Next: [`02-recon.md`](02-recon.md).
