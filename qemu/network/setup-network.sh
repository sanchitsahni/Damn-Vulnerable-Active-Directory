#!/usr/bin/env bash
# ==============================================================================
# DVAD Network Setup - QEMU Bridge Networks
# ==============================================================================
set -euo pipefail

NET_BASE="10.10.0"
NET_FINANCE="10.20.0"
NET_ROOT="10.30.0"
NET_MGMT="10.0.2"

BRIDGE_CTF="dvad-ctf"
BRIDGE_FINANCE="dvad-finance"
BRIDGE_ROOT="dvad-root"

# Bring up bridge networks for isolated lab segments
create_network_bridge() {
    local name="$1"
    local subnet="$2"
    local gateway="$3"

    # Check if bridge already exists
    if ip link show "$name" &>/dev/null; then
        info "Bridge $name already exists."
        # Allow qemu-bridge-helper for this bridge
        sudo mkdir -p /etc/qemu
        if ! sudo grep -q "^allow $name\$" /etc/qemu/bridge.conf 2>/dev/null; then
            echo "allow $name" | sudo tee -a /etc/qemu/bridge.conf >/dev/null
        fi
        return 0
    fi

    log "Creating bridge: $name ($subnet/24, gw $gateway)"

    # Create bridge
    sudo ip link add name "$name" type bridge
    sudo ip addr add "${gateway}/24" dev "$name"
    sudo ip link set "$name" up

    # Allow qemu-bridge-helper for this bridge
    sudo mkdir -p /etc/qemu
    if ! sudo grep -q "^allow $name\$" /etc/qemu/bridge.conf 2>/dev/null; then
        echo "allow $name" | sudo tee -a /etc/qemu/bridge.conf >/dev/null
    fi

    # Enable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Add nftables/iptables rules for NAT and isolation
    if command -v nft &>/dev/null && nft list tables 2>/dev/null | grep -q dvad; then
        # nftables already configured
        :
    elif command -v nft &>/dev/null; then
        sudo nft add table inet dvad
        sudo nft add chain inet dvad forward '{ type filter hook forward priority 0; policy accept; }'
        sudo nft add chain inet dvad nat '{ type nat hook postrouting priority 100; policy accept; }'

        # NAT for internet access during install (restricted to install phase)
        sudo nft add rule inet dvad nat oifname "eth0" masquerade 2>/dev/null || \
        sudo nft add rule inet dvad nat oifname "wlan0" masquerade 2>/dev/null || \
        sudo nft add rule inet dvad nat oifname "ens*" masquerade 2>/dev/null || true
    else
        # Fallback to iptables
        sudo iptables -t nat -A POSTROUTING -s "${subnet}/24" -j MASQUERADE 2>/dev/null || true
        sudo iptables -A FORWARD -i "$name" -j ACCEPT 2>/dev/null || true
        sudo iptables -A FORWARD -o "$name" -j ACCEPT 2>/dev/null || true
    fi

    log "Bridge $name created."
}

# Setup dnsmasq for DHCP during VM bootstrap
setup_dnsmasq() {
    log "Configuring dnsmasq for DHCP on lab networks..."

    local DHCP_BASE="/tmp/dvad-dnsmasq"
    mkdir -p "$DHCP_BASE"

    cat > "${DHCP_BASE}/dvad-dnsmasq.conf" << 'DNSMASQ_EOF'
# DVAD Lab DHCP Configuration
bind-interfaces
no-resolv
domain-needed
bogus-priv
conf-file=/tmp/dvad-dnsmasq/dvad-static.conf

# CTF Network (corp.local + eu.corp.local)
interface=dvad-ctf
dhcp-range=10.10.0.150,10.10.0.200,255.255.248.0,12h
dhcp-option=dvad-ctf,3,10.10.0.1
dhcp-option=dvad-ctf,6,10.10.0.10
dhcp-option=dvad-ctf,15,corp.local

# Finance Network
interface=dvad-finance
dhcp-range=10.20.0.100,10.20.0.200,255.255.255.0,12h
dhcp-option=dvad-finance,3,10.20.0.1
dhcp-option=dvad-finance,6,10.20.0.10
dhcp-option=dvad-finance,15,finance.local

# Root Network
interface=dvad-root
dhcp-range=10.30.0.100,10.30.0.200,255.255.255.0,12h
dhcp-option=dvad-root,3,10.30.0.1
dhcp-option=dvad-root,6,10.30.0.10
dhcp-option=dvad-root,15,root.corp
DNSMASQ_EOF

    # Kill any existing dnsmasq
    sudo pkill -f "dnsmasq.*dvad" 2>/dev/null || true

    # Start dnsmasq
    sudo dnsmasq --conf-file="${DHCP_BASE}/dvad-dnsmasq.conf" \
        --pid-file="${DHCP_BASE}/dvad-dnsmasq.pid" \
        --log-facility="${DHCP_BASE}/dvad-dnsmasq.log" &

    sleep 1
    if [ -f "${DHCP_BASE}/dvad-dnsmasq.pid" ]; then
        log "Dnsmasq DHCP started (PID: $(cat ${DHCP_BASE}/dvad-dnsmasq.pid))"
    else
        warn "Dnsmasq may not have started. Check ${DHCP_BASE}/dvad-dnsmasq.log"
    fi
}

# Reserve static IPs in dnsmasq
add_static_leases() {
    local LEASE_FILE="/tmp/dvad-dnsmasq/dvad-static.conf"
    mkdir -p "/tmp/dvad-dnsmasq"

    cat > "$LEASE_FILE" << 'STATIC_EOF'
# Static DHCP Leases for DVAD Lab
# Corp Domain
dhcp-host=52:54:00:00:01:01,dc01.corp.local,10.10.0.10
dhcp-host=52:54:00:00:01:02,dc01.eu.corp.local,10.10.0.11
dhcp-host=52:54:00:00:01:03,ca01.corp.local,10.10.0.12
dhcp-host=52:54:00:00:01:04,file01.corp.local,10.10.0.13
dhcp-host=52:54:00:00:01:05,sql01.corp.local,10.10.0.14
dhcp-host=52:54:00:00:01:06,ws01.corp.local,10.10.0.100
# Finance Domain
dhcp-host=52:54:00:00:02:01,dc01.finance.local,10.20.0.10
# Root Domain
dhcp-host=52:54:00:00:03:01,dc01.root.corp,10.30.0.10
STATIC_EOF

    log "Static DHCP leases configured."
}

create_all_networks() {
    echo "=== DVAD Network Setup ==="

    create_network_bridge "$BRIDGE_CTF" "$NET_BASE" "${NET_BASE}.1"
    create_network_bridge "$BRIDGE_FINANCE" "$NET_FINANCE" "${NET_FINANCE}.1"
    create_network_bridge "$BRIDGE_ROOT" "$NET_ROOT" "${NET_ROOT}.1"

    # Optionally create NAT bridge for internet access during install
    if ! ip link show dvad-nat &>/dev/null; then
        sudo ip link add name dvad-nat type bridge 2>/dev/null || true
        sudo ip addr add 10.0.2.1/24 dev dvad-nat 2>/dev/null || true
        sudo ip link set dvad-nat up 2>/dev/null || true
    fi

    add_static_leases
    setup_dnsmasq

    # Show bridge status
    echo ""
    log "Network bridges:"
    ip -br link show | grep dvad || true
    echo ""

    log "Network setup complete."
}

# Cleanup function
destroy_all_networks() {
    warn "Destroying DVAD networks..."

    # Kill dnsmasq
    sudo pkill -f "dnsmasq.*dvad" 2>/dev/null || true
    rm -rf /tmp/dvad-dnsmasq

    # Remove bridges
    for br in dvad-ctf dvad-finance dvad-root dvad-nat; do
        sudo ip link set "$br" down 2>/dev/null || true
        sudo ip link delete "$br" 2>/dev/null || true
    done

    # Clean firewall rules
    if command -v nft &>/dev/null; then
        sudo nft delete table inet dvad 2>/dev/null || true
    fi

    log "Networks destroyed."
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
    warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
    info() { echo -e "\033[0;34m[*]\033[0m $*"; }
    case "${1:-create}" in
        create)  create_all_networks ;;
        destroy) destroy_all_networks ;;
        *)       echo "Usage: $0 [create|destroy]"; exit 1 ;;
    esac
fi
