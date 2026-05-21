#!/usr/bin/env bash
# ==============================================================================
# DVAD - VPS WireGuard Gateway
# Spins up a WireGuard server on the VPS that routes the attacker peer
# into the lab subnets (10.10.0.0/21 + 10.20.0.0/24 + 10.30.0.0/24).
#
# Usage:
#   sudo bash scripts/vps-wg-gateway.sh up        # install, configure, start, print client conf
#   sudo bash scripts/vps-wg-gateway.sh down      # stop wg + delete server config
#   sudo bash scripts/vps-wg-gateway.sh status    # show wg status + connected peers
#
# Environment overrides (optional):
#   WG_PORT=51820                    UDP port the VPS will listen on
#   WG_SERVER_ADDR=10.99.0.1/24      WG-internal address of the server
#   WG_CLIENT_ADDR=10.99.0.2/32      WG-internal address assigned to the attacker peer
#   WG_NET=10.99.0.0/24              WG tunnel subnet
#   WG_IFACE=wg-dvad                 Interface name
#   LAB_SUBNETS="10.10.0.0/21 10.20.0.0/24 10.30.0.0/24"   Routed into the tunnel
#   WG_DIR=/etc/wireguard            Where server config lives
#   OUT_CLIENT_CONF=./dvad-attacker.conf   Where to write the attacker conf
#
# After 'up', copy the printed conf (or the file at $OUT_CLIENT_CONF) to your
# Kali / BlackArch laptop, then:
#   sudo wg-quick up ./dvad-attacker.conf
#   nxc smb 10.10.0.10 -u alice -p 'DVADlab2024!'
#
# Security note:
#   Every VM in DVAD is intentionally vulnerable. DO NOT publish the lab
#   subnets to the internet directly. This script firewalls inbound traffic so
#   ONLY the WG port + (optionally) SSH reach the VPS; all attacker access to
#   the lab is forced through the WG tunnel.
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# ---- defaults ----------------------------------------------------------------
WG_PORT="${WG_PORT:-51820}"
WG_SERVER_ADDR="${WG_SERVER_ADDR:-10.99.0.1/24}"
WG_CLIENT_ADDR="${WG_CLIENT_ADDR:-10.99.0.2/32}"
WG_NET="${WG_NET:-10.99.0.0/24}"
WG_IFACE="${WG_IFACE:-wg-dvad}"
LAB_SUBNETS="${LAB_SUBNETS:-10.10.0.0/21 10.20.0.0/24 10.30.0.0/24}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
OUT_CLIENT_CONF="${OUT_CLIENT_CONF:-./dvad-attacker.conf}"

ACTION="${1:-up}"

# ---- logging -----------------------------------------------------------------
log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }
err()  { echo -e "\033[0;31m[-]\033[0m $*" >&2; }

# ---- guards ------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must run as root (it edits /etc/wireguard and nftables)."
        exit 1
    fi
}

# ---- install wireguard + nftables --------------------------------------------
install_deps() {
    if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
        info "WireGuard already installed."
    else
        log "Installing WireGuard..."
        if   command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y wireguard wireguard-tools qrencode iptables nftables
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y wireguard-tools qrencode iptables nftables
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm wireguard-tools qrencode iptables nftables
        elif command -v zypper >/dev/null 2>&1; then
            zypper install -y wireguard-tools qrencode iptables nftables
        else
            err "Unsupported package manager. Install wireguard-tools manually."
            exit 1
        fi
    fi
}

# ---- detect WAN interface ----------------------------------------------------
detect_wan() {
    local iface
    iface="$(ip -4 route show default | awk '{print $5; exit}')"
    if [ -z "${iface:-}" ]; then
        err "Could not detect default-route interface; set WAN_IFACE manually."
        exit 1
    fi
    echo "$iface"
}

# ---- key management ----------------------------------------------------------
ensure_keys() {
    mkdir -p "${WG_DIR}"
    chmod 700 "${WG_DIR}"
    umask 077
    if [ ! -f "${WG_DIR}/server_private.key" ]; then
        log "Generating server keypair..."
        wg genkey | tee "${WG_DIR}/server_private.key" | wg pubkey > "${WG_DIR}/server_public.key"
    fi
    if [ ! -f "${WG_DIR}/client_private.key" ]; then
        log "Generating attacker (client) keypair..."
        wg genkey | tee "${WG_DIR}/client_private.key" | wg pubkey > "${WG_DIR}/client_public.key"
    fi
    chmod 600 "${WG_DIR}"/*.key
}

# ---- write server conf -------------------------------------------------------
write_server_conf() {
    local wan="$1"
    local srv_priv srv_pub cli_pub
    srv_priv="$(cat "${WG_DIR}/server_private.key")"
    srv_pub="$(cat "${WG_DIR}/server_public.key")"
    cli_pub="$(cat "${WG_DIR}/client_public.key")"

    local allowed_for_client="${WG_CLIENT_ADDR}"

    cat > "${WG_DIR}/${WG_IFACE}.conf" <<EOF
# DVAD WireGuard Gateway — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
[Interface]
PrivateKey = ${srv_priv}
Address    = ${WG_SERVER_ADDR}
ListenPort = ${WG_PORT}

# Route attacker traffic into the lab + masquerade out the lab bridges so the
# Windows VMs see the source as the VPS, not the WG tunnel address (VPN
# clients otherwise look like 10.99.0.2 to Windows, which trips host firewall
# / SMB-restriction logic on some Windows configs).
#
# We explicitly FORWARD between wg-dvad and every DVAD bridge, in case the
# host's default FORWARD policy is DROP (common on hardened VPSes). Bridges
# created by qemu/network/setup-network.sh: dvad-ctf, dvad-finance, dvad-root.
PostUp   = sysctl -w net.ipv4.ip_forward=1
PostUp   = iptables -A FORWARD -i %i -o ${wan} -j ACCEPT
PostUp   = iptables -A FORWARD -i ${wan} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp   = iptables -A FORWARD -i %i -o dvad-ctf -j ACCEPT
PostUp   = iptables -A FORWARD -o %i -i dvad-ctf -j ACCEPT
PostUp   = iptables -A FORWARD -i %i -o dvad-finance -j ACCEPT
PostUp   = iptables -A FORWARD -o %i -i dvad-finance -j ACCEPT
PostUp   = iptables -A FORWARD -i %i -o dvad-root -j ACCEPT
PostUp   = iptables -A FORWARD -o %i -i dvad-root -j ACCEPT
PostUp   = iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${wan} -j MASQUERADE
$(for sn in ${LAB_SUBNETS}; do
    echo "PostUp   = iptables -t nat -A POSTROUTING -s ${WG_NET} -d ${sn} -j MASQUERADE"
done)
PostDown = iptables -D FORWARD -i %i -o ${wan} -j ACCEPT || true
PostDown = iptables -D FORWARD -i ${wan} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT || true
PostDown = iptables -D FORWARD -i %i -o dvad-ctf -j ACCEPT || true
PostDown = iptables -D FORWARD -o %i -i dvad-ctf -j ACCEPT || true
PostDown = iptables -D FORWARD -i %i -o dvad-finance -j ACCEPT || true
PostDown = iptables -D FORWARD -o %i -i dvad-finance -j ACCEPT || true
PostDown = iptables -D FORWARD -i %i -o dvad-root -j ACCEPT || true
PostDown = iptables -D FORWARD -o %i -i dvad-root -j ACCEPT || true
PostDown = iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${wan} -j MASQUERADE || true
$(for sn in ${LAB_SUBNETS}; do
    echo "PostDown = iptables -t nat -D POSTROUTING -s ${WG_NET} -d ${sn} -j MASQUERADE || true"
done)

# Attacker peer
[Peer]
# attacker (Kali / BlackArch laptop)
PublicKey  = ${cli_pub}
AllowedIPs = ${allowed_for_client}
EOF
    chmod 600 "${WG_DIR}/${WG_IFACE}.conf"
}

# ---- write client conf -------------------------------------------------------
write_client_conf() {
    local endpoint_host="$1"
    local cli_priv srv_pub
    cli_priv="$(cat "${WG_DIR}/client_private.key")"
    srv_pub="$(cat "${WG_DIR}/server_public.key")"

    # Route only the lab subnets through the tunnel — your laptop keeps normal
    # internet via its real default route.
    local allowed_csv
    allowed_csv="${WG_NET}"
    for sn in ${LAB_SUBNETS}; do
        allowed_csv="${allowed_csv}, ${sn}"
    done

    cat > "${OUT_CLIENT_CONF}" <<EOF
# DVAD attacker peer — paste on your Kali / BlackArch laptop
# Save as dvad-attacker.conf, then: sudo wg-quick up ./dvad-attacker.conf
[Interface]
PrivateKey = ${cli_priv}
Address    = ${WG_CLIENT_ADDR}
# DNS not set on purpose — Windows VMs use the lab DNS; the attacker resolves
# lab hostnames via /etc/hosts (see docs/01-setup.md).

[Peer]
PublicKey  = ${srv_pub}
Endpoint   = ${endpoint_host}:${WG_PORT}
AllowedIPs = ${allowed_csv}
PersistentKeepalive = 25
EOF
    chmod 600 "${OUT_CLIENT_CONF}"
}

# ---- detect public endpoint --------------------------------------------------
detect_public_ip() {
    local ip
    ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [ -z "${ip}" ]; then
        ip="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    fi
    if [ -z "${ip}" ]; then
        ip="$(ip -4 addr show "$(detect_wan)" | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
    fi
    echo "${ip}"
}

# ---- actions -----------------------------------------------------------------
do_up() {
    require_root
    install_deps
    ensure_keys

    local wan endpoint
    wan="$(detect_wan)"
    endpoint="${WG_ENDPOINT:-$(detect_public_ip)}"
    if [ -z "${endpoint}" ]; then
        err "Could not auto-detect public IP. Set WG_ENDPOINT=<ip-or-host> and re-run."
        exit 1
    fi
    info "WAN interface : ${wan}"
    info "Public endpoint: ${endpoint}:${WG_PORT}/udp"
    info "Lab subnets   : ${LAB_SUBNETS}"

    write_server_conf "${wan}"
    write_client_conf "${endpoint}"

    # IP forwarding persistent
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Stop any existing instance, then bring it up
    wg-quick down "${WG_IFACE}" 2>/dev/null || true
    wg-quick up "${WG_IFACE}"
    systemctl enable "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true

    log "WireGuard gateway is up."
    echo
    echo "======================================================================"
    echo " Attacker peer config written to: ${OUT_CLIENT_CONF}"
    echo "----------------------------------------------------------------------"
    cat "${OUT_CLIENT_CONF}"
    echo "======================================================================"
    echo
    log "Next steps on your Kali / BlackArch laptop:"
    echo "   scp root@${endpoint}:${OUT_CLIENT_CONF} ./dvad-attacker.conf"
    echo "   sudo wg-quick up ./dvad-attacker.conf"
    echo "   ping 10.10.0.10        # dc01.corp.local"
    echo "   nxc smb 10.10.0.10 -u alice -p 'DVADlab2024!'"
    echo
    warn "DO NOT expose the lab subnets directly. Confirm with: iptables -t nat -L POSTROUTING -n"
}

do_down() {
    require_root
    wg-quick down "${WG_IFACE}" 2>/dev/null || true
    systemctl disable "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
    log "WireGuard gateway is down. (Config left at ${WG_DIR}/${WG_IFACE}.conf — delete manually if you want a clean slate.)"
}

do_status() {
    if ! command -v wg >/dev/null 2>&1; then
        err "wg not installed."
        exit 1
    fi
    wg show "${WG_IFACE}" 2>/dev/null || warn "Interface ${WG_IFACE} not active."
    echo
    info "NAT rules touching ${WG_NET}:"
    iptables -t nat -S POSTROUTING | grep -F "${WG_NET}" || echo "  (none)"
}

case "${ACTION}" in
    up)     do_up ;;
    down)   do_down ;;
    status) do_status ;;
    *)      err "Unknown action: ${ACTION}"; echo "Usage: $0 {up|down|status}"; exit 1 ;;
esac
