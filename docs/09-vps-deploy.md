# 09 — Running DVAD on a VPS (WireGuard gateway)

DVAD on a VPS is the same lab as DVAD on your desk — eight intentionally
vulnerable Windows VMs sitting on three private bridges. The VPS-specific
problem is **reachability**: your attacker box (Kali / BlackArch) is no longer
on the same Ethernet as the lab. The solution this repo ships with is a
WireGuard gateway running on the VPS that pulls your laptop into the lab
subnets over a single UDP port.

```
                              ┌─────────────────────────────────────────────────┐
                              │                     VPS                          │
                              │                                                  │
   Internet                   │   wg-dvad (51820/udp)  ─┐                        │
   ─────────►  UDP/51820 ────►│   10.99.0.1/24          │ MASQUERADE             │
                              │                         ▼                        │
   Your laptop                │   ┌──────────────────────────────────────────┐  │
   ┌───────────────┐          │   │ Linux bridges (dvad-ctf / dvad-finance / │  │
   │  Kali / Black │          │   │ dvad-root) + dnsmasq                     │  │
   │  10.99.0.2    │ ◄────────┤   └────┬──────────────┬───────────────┬──────┘  │
   │               │   WG     │        ▼              ▼               ▼         │
   │  routes:      │  tunnel  │   corp.local      finance.local   root.corp     │
   │   10.10/21    │          │   10.10.0.0/21   10.20.0.0/24    10.30.0.0/24   │
   │   10.20/24    │          │   (8 vulnerable Windows VMs)                     │
   │   10.30/24    │          │                                                  │
   └───────────────┘          └─────────────────────────────────────────────────┘
```

Only **one** inbound port reaches the VPS from the internet (the WG port).
Everything else — SMB, LDAP, Kerberos, WinRM, RPC — is reachable **only**
after the attacker peer has authenticated and brought the tunnel up.

---

## Why a tunnel, not port forwarding

You will be tempted to `iptables -t nat -A PREROUTING -p tcp --dport 445 -j DNAT ...`
and call it a day. Don't. DVAD is **intentionally vulnerable**. Exposing
SMB 445 / LDAP 389 / Kerberos 88 / WinRM 5985 / RDP 3389 / MSSQL 1433 / WebDAV
/ NFS / Telnet / FTP / etc. directly to the internet means:

1. Anyone in the world can hit the lab and use it as a relay / phishing pad
   (lab service accounts have known weak passwords).
2. Your VPS provider's abuse desk will receive complaints inside 24h.
3. Many of the exploits used inside the lab (PetitPotam, NTLM relay, mitm6,
   coercion chains) work just as well against the public internet if relayed
   outbound through the VPS — your VPS becomes the attacker.

WireGuard fixes all three: only your peer key can reach the tunnel, and only
attacker → lab traffic crosses it.

---

## Resource budget on the VPS

| Profile | Min RAM | Min vCPU | Disk | Typical VPS plan |
|---|---|---|---|---|
| `./deploy.sh --vps --single-dc` | 4 GB | 2 | 30 GB | Hetzner CX22, DO 4 GB |
| `./deploy.sh --vps --minimal`   | 16 GB | 6 | 80 GB | Hetzner CX52, Vultr 16 GB |
| `./deploy.sh --vps` (full 8 VM) | 24 GB | 8 | 120 GB | Hetzner CCX33, dedicated |

The `--vps` flag forces VNC to bind on `127.0.0.1` (so you can SSH-tunnel
to a console without exposing VNC to the world) and pre-flights host capacity.

---

## Deploy

### 1. Build the lab on the VPS

```bash
ssh root@your-vps
git clone <this-repo> DVAD
cd DVAD
./deploy.sh --vps                    # 45–90 min — Windows install dominates
```

### 2. Bring up the WireGuard gateway

```bash
sudo bash scripts/vps-wg-gateway.sh up
```

This script:

1. Installs `wireguard-tools` (apt/dnf/pacman/zypper auto-detected).
2. Generates server + client keypairs in `/etc/wireguard/`.
3. Writes `/etc/wireguard/wg-dvad.conf` (server, listens on `51820/udp`).
4. Enables IPv4 forwarding + adds NAT rules so the attacker peer
   (`10.99.0.2`) masquerades into the lab bridges.
5. Brings the interface up with `wg-quick` and enables it on boot.
6. Writes `./dvad-attacker.conf` and **prints it to stdout** — that's your
   client config.

```bash
sudo bash scripts/vps-wg-gateway.sh status   # see connected peers
sudo bash scripts/vps-wg-gateway.sh down     # stop the tunnel
```

### 3. Attacker side (your laptop)

```bash
# Grab the printed conf (or scp it):
scp root@your-vps:DVAD/dvad-attacker.conf .

# Bring it up:
sudo wg-quick up ./dvad-attacker.conf

# Verify reachability:
ping -c1 10.10.0.10                                  # dc01.corp.local
nxc smb 10.10.0.10 -u peter.parker -p 'DVADlab2024!'        # full lab is yours
```

The client conf only routes the three lab subnets (`10.10.0.0/21`,
`10.20.0.0/24`, `10.30.0.0/24`) — your laptop keeps its normal default
route for the rest of the internet.

### 4. Make lab hostnames resolve

Add to your laptop's `/etc/hosts` (or the entries from `docs/01-setup.md`):

```
10.10.0.10  dc01.corp.local corp.local
10.10.0.11  dc01.eu.corp.local eu.corp.local
10.10.0.12  ca01.corp.local
10.10.0.13  file01.corp.local
10.10.0.14  sql01.corp.local
10.10.0.100 ws01.corp.local
10.20.0.10  dc01.finance.local finance.local
10.30.0.10  dc01.root.corp root.corp
```

You can also dump these via `nslookup` once you're inside the tunnel — the
lab DNS on `dc01.corp.local` is reachable as a normal nameserver.

---

## Firewall hardening on the VPS

The gateway script only opens the WG port. Belt-and-braces — block everything
else inbound on the WAN interface:

```bash
# UFW example (Debian/Ubuntu)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp                # your SSH — restrict to your /32 if you can
ufw allow 51820/udp             # WireGuard
ufw enable

# nftables equivalent (RHEL/Fedora/Arch)
nft add table inet dvad
nft add chain inet dvad input '{ type filter hook input priority 0 ; policy drop ; }'
nft add rule inet dvad input ct state established,related accept
nft add rule inet dvad input iif lo accept
nft add rule inet dvad input tcp dport 22 accept
nft add rule inet dvad input udp dport 51820 accept
```

Critical: **do not** open 445 / 389 / 88 / 5985 / 3389 / 1433 / 80 / 443
on the WAN interface. If you accidentally do, the lab will be ingested by
opportunistic scanners within hours.

---

## VNC over SSH (for console access when something is wedged)

```bash
# On your laptop, tunnel VNC port 5901 from the VPS to localhost:
ssh -L 5901:127.0.0.1:5901 root@your-vps
# In another terminal:
vncviewer 127.0.0.1:5901
```

VNC ports per VM are in `qemu/vm-create.sh` (`VM_DEFS` table).

---

## Routing failure checklist

| Symptom | Cause | Fix |
|---|---|---|
| `wg-quick up` succeeds on laptop but no ping to `10.10.0.10` | IP forwarding off on VPS | `sysctl -w net.ipv4.ip_forward=1` (the script does this; check `/proc/sys/net/ipv4/ip_forward` = 1) |
| Ping works, but SMB / WinRM time out | Windows firewall — but post-install.ps1 disables it. Re-run Ansible. | `cd ansible && ansible-playbook -i inventory.yml playbooks/site.yml --tags windows_base` |
| Asymmetric routing: TCP SYN reaches lab, SYN-ACK lost | NAT MASQUERADE missing for that subnet | `iptables -t nat -L POSTROUTING -n` should show one MASQUERADE per lab subnet |
| Tunnel works for `corp.local` (10.10/21) but not `finance.local` (10.20/24) | Attacker peer's `AllowedIPs` doesn't list 10.20.0.0/24 | Re-generate client conf with `vps-wg-gateway.sh up` — it includes all three subnets |
| Latency feels awful | Path-MTU between VPS and laptop | Add `MTU = 1380` under `[Interface]` on the laptop conf |

---

## Cleanup

```bash
sudo bash scripts/vps-wg-gateway.sh down     # stop tunnel
bash qemu/vm-create.sh destroy               # delete VMs
bash qemu/network/setup-network.sh destroy   # tear down bridges + dnsmasq
```

The WG server config at `/etc/wireguard/wg-dvad.conf` and the keypairs in
`/etc/wireguard/*.key` are intentionally left in place after `down` — delete
them by hand if you want a clean slate.

---

## See also

- `scripts/vps-wg-gateway.sh` — the script itself; read it before running
- [`01-setup.md`](01-setup.md) — attacker-box prep (Kali tools, /etc/hosts, krb5.conf)
- [`02a-initial-access.md`](02a-initial-access.md) — IA-001..050 — once you're in the tunnel, this is where you start
- `README.md` — quick-start
