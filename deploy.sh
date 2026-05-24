#!/usr/bin/env bash
# ==============================================================================
# DVAD - Deployable Vulnerable Active Directory Lab
# Enterprise CTF Challenge - Single Command Deployment
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DVAD_HOME="$SCRIPT_DIR"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   DVAD - Deployable Vulnerable Active Directory Lab      ║"
    echo "║   Enterprise CTF - Game of AD v2.0                       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

banner

# ==============================================================================
# Configuration
# ==============================================================================
CFG_MEM_TOTAL=""
CFG_CPU_TOTAL=""
CFG_DISK_PATH="${DVAD_HOME}/vms"
CFG_MEDIA_PATH="${DVAD_HOME}/media"
CFG_DEPLOY_MODE="full"  # full | minimal | single-dc
CFG_VPS_MODE="0"        # 1 = headless VPS (no GUI, VNC on loopback, larger VM sizing)
CFG_VNC_BIND="127.0.0.1" # interface to bind VNC sockets to
export CFG_MEM_TOTAL CFG_CPU_TOTAL CFG_DISK_PATH CFG_MEDIA_PATH CFG_DEPLOY_MODE CFG_VPS_MODE CFG_VNC_BIND

# ==============================================================================
# Phase 0: OS Detection & Dependency Installation
# ==============================================================================
detect_os() {
    source /etc/os-release 2>/dev/null || true
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)  PKG_MGR="apt";  ;;
        fedora|rhel|centos|rocky|alma) PKG_MGR="dnf";  ;;
        arch|manjaro|endeavouros)      PKG_MGR="pacman";;
        opensuse*|sles)                PKG_MGR="zypper";;
        *) warn "Unknown OS: $OS_ID. Attempting apt fallback"; PKG_MGR="apt";;
    esac
    log "Detected OS: $OS_ID $OS_VERSION"
    log "Package manager: $PKG_MGR"
}

install_dependencies() {
    log "Installing required dependencies..."
    case "$PKG_MGR" in
        apt)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                qemu-system-x86 qemu-utils qemu-kvm \
                libvirt-daemon-system libvirt-clients bridge-utils \
                virt-manager ansible python3 python3-pip \
                python3-libvirt swtpm ovmf \
                cloud-image-utils genisoimage wget curl \
                jq unzip p7zip-full nftables dnsmasq \
                aria2 openssh-client git 2>/dev/null || sudo apt-get install -y -qq \
                qemu-system-x86 qemu-utils qemu-kvm \
                libvirt-daemon-system libvirt-clients bridge-utils \
                ansible python3 python3-pip genisoimage wget curl jq unzip aria2 openssh-client git
            ;;
        dnf)
            sudo dnf install -y \
                qemu-kvm qemu-img libvirt virt-install \
                ansible python3-pip swtpm edk2-ovmf \
                genisoimage wget curl jq unzip aria2 \
                nftables dnsmasq openssh-clients git
            sudo systemctl enable --now libvirtd 2>/dev/null || true
            ;;
        pacman)
            sudo pacman -S --noconfirm \
                qemu-desktop libvirt virt-manager swtpm edk2-ovmf \
                ansible python-pip cdrtools wget curl jq unzip aria2 \
                nftables dnsmasq openssh git
            sudo systemctl enable --now libvirtd 2>/dev/null || true
            ;;
        zypper)
            sudo zypper install -y \
                qemu-kvm qemu-tools libvirt virt-manager \
                ansible python3-pip swtpm ovmf \
                genisoimage wget curl jq unzip aria2 \
                nftables dnsmasq openssh-clients git
            sudo systemctl enable --now libvirtd 2>/dev/null || true
            ;;
    esac

    # Install Python dependencies
    pip3 install --user pywinrm cryptography passlib 2>/dev/null || pip3 install pywinrm cryptography passlib 2>/dev/null || true

    # Ensure user is in libvirt/kvm groups
    if ! groups "$USER" | grep -qE '\b(libvirt|kvm)\b'; then
        warn "Adding user to kvm/libvirt groups..."
        sudo usermod -aG kvm,libvirt "$USER" 2>/dev/null || true
        warn "You may need to log out and back in for group changes to take effect."
    fi

    log "Dependencies installed successfully."
}

check_kvm() {
    if [ -e /dev/kvm ]; then
        log "KVM acceleration available."
        KVM_OPT="-enable-kvm"
    else
        warn "KVM not available. Using software emulation (SLOW)."
        KVM_OPT=""
    fi
}

# ==============================================================================
# Phase 1: Network Setup
# ==============================================================================
setup_networks() {
    log "Setting up virtual networks..."
    source "${DVAD_HOME}/qemu/network/setup-network.sh"
    create_all_networks
    log "Virtual networks configured."
}

# ==============================================================================
# Phase 2: Windows Media Download
# ==============================================================================
download_windows_media() {
    log "Checking Windows installation media..."
    source "${DVAD_HOME}/scripts/download-windows.sh"
    ensure_media
    log "Windows media ready."
}

# ==============================================================================
# Phase 2.5: Convert VHD to QCOW2 Master Template
# ==============================================================================
convert_master_template() {
    local vhd_file="${CFG_MEDIA_PATH}/windows-server-2022-eval.vhd"
    local base_qcow2="${CFG_MEDIA_PATH}/win2k25.qcow2"

    if [ ! -f "$base_qcow2" ]; then
        log "Converting VHD to QCOW2 master template (this takes a few minutes)..."
        if [ ! -f "$vhd_file" ]; then
            err "VHD file not found: $vhd_file. Cannot convert to QCOW2."
            exit 1
        fi
        qemu-img convert -O qcow2 "$vhd_file" "$base_qcow2"
        log "Master QCOW2 template created successfully."
    else
        info "Master QCOW2 template already exists: $base_qcow2"
    fi
}

# ==============================================================================
# Phase 3: VM Creation & Deployment
# ==============================================================================
create_vms() {
    log "Creating QEMU virtual machines..."
    source "${DVAD_HOME}/qemu/vm-create.sh"
    create_all_vms
    log "All VMs created and booting."
}

# ==============================================================================
# Phase 4: Wait for VM readiness
# ==============================================================================
wait_for_vms() {
    log "Waiting for all VMs to complete Windows installation..."
    source "${DVAD_HOME}/scripts/wait-vms.sh"
    wait_for_all
    log "All VMs ready."
}

# ==============================================================================
# Phase 5: Post-Install Activation
# ==============================================================================
activate_windows() {
    log "Activating Windows via Massgrave..."
    source "${DVAD_HOME}/scripts/activate-windows.sh"
    activate_all
    log "Windows activated."
}

# ==============================================================================
# Phase 6: Ansible Provisioning & Vulnerability Injection
# ==============================================================================
run_ansible() {
    log "Running Ansible playbooks for AD provisioning and vulnerability injection..."
    
    local ansible_dir="${DVAD_HOME}/ansible"
    if [ "$CFG_DEPLOY_MODE" = "single-dc" ]; then
        ansible_dir="${DVAD_HOME}/ansible-single-dc"
        log "Mode: single-dc. Using ${ansible_dir}"
    elif [ "$CFG_DEPLOY_MODE" = "minimal" ]; then
        ansible_dir="${DVAD_HOME}/ansible-minimal"
        log "Mode: minimal. Using ${ansible_dir}"
    else
        ansible_dir="${DVAD_HOME}/ansible-full"
        log "Mode: full. Using ${ansible_dir}"
    fi

    cd "$ansible_dir"
    ansible-playbook -i inventory.yml playbooks/site.yml -v
    log "Ansible provisioning complete."
}

# ==============================================================================
# Phase 7: Verification & Finalization
# ==============================================================================
finalize() {
    log "Running final verification..."
    source "${DVAD_HOME}/scripts/finalize.sh"
    run_verification
    log "Lab deployment complete!"
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --minimal) CFG_DEPLOY_MODE="minimal"; shift;;
            --single-dc) CFG_DEPLOY_MODE="single-dc"; shift;;
            --vps) CFG_VPS_MODE="1"; shift;;
            --vnc-bind) CFG_VNC_BIND="$2"; shift 2;;
            --memory) CFG_MEM_TOTAL="$2"; shift 2;;
            --cpus) CFG_CPU_TOTAL="$2"; shift 2;;
            --disk-path) CFG_DISK_PATH="$2"; shift 2;;
            --help|-h)
                cat <<EOF
Usage: ./deploy.sh [--minimal|--single-dc] [--vps] [--memory GB] [--cpus N]
                   [--disk-path PATH] [--vnc-bind ADDR]

  --minimal       Deploy only corp.local domain (5 VMs, ~12GB RAM)
  --single-dc     Deploy single DC for quick testing (1 VM, ~3GB RAM)
  --vps           Headless VPS profile: bigger per-VM RAM, VNC on loopback only,
                  pre-flight host-capacity check, no display devices.
                  Recommended for 64GB / 16-core VPS hosts.
  --memory GB     Target total RAM budget across all VMs (default: 18 full / 28 vps).
                  Per-VM RAM is scaled proportionally.
  --cpus N        Total vCPU budget across all VMs (default: 10 full / 14 vps).
                  Per-VM vCPUs are scaled proportionally with a floor of 1.
  --disk-path P   Override VM disk storage directory (default: ./vms).
  --vnc-bind ADDR Bind VNC sockets to ADDR (default: 127.0.0.1; "0.0.0.0" exposes
                  VNC on all interfaces - only safe behind a firewall/VPN).
EOF
                exit 0;;
            *) err "Unknown option: $1"; exit 1;;
        esac
    done

    # Apply VPS defaults if --vps was passed and the user did not override.
    if [ "$CFG_VPS_MODE" = "1" ]; then
        : "${CFG_MEM_TOTAL:=28}"
        : "${CFG_CPU_TOTAL:=14}"
        export CFG_MEM_TOTAL CFG_CPU_TOTAL CFG_VPS_MODE CFG_VNC_BIND
        log "VPS mode enabled (headless, VNC bound to ${CFG_VNC_BIND}, mem=${CFG_MEM_TOTAL}G cpus=${CFG_CPU_TOTAL})"
    fi
    export CFG_DEPLOY_MODE CFG_DISK_PATH CFG_MEM_TOTAL CFG_CPU_TOTAL CFG_VPS_MODE CFG_VNC_BIND

    # Host capacity pre-flight (warn loudly, do not block - user may know better).
    local host_mem_gb host_cpus
    host_mem_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
    host_cpus=$(nproc)
    info "Host: ${host_mem_gb}GB RAM, ${host_cpus} vCPUs"
    local need_mem=18
    [ "$CFG_DEPLOY_MODE" = "minimal" ]   && need_mem=12
    [ "$CFG_DEPLOY_MODE" = "single-dc" ] && need_mem=4
    [ -n "$CFG_MEM_TOTAL" ] && need_mem="$CFG_MEM_TOTAL"
    if [ "$host_mem_gb" -lt $(( need_mem + 4 )) ]; then
        warn "Host has ${host_mem_gb}GB RAM but deploy needs ~${need_mem}GB for guests + 4GB host overhead."
        warn "Continuing anyway; OOM-killer may strike. Use --memory to cap, or pick --minimal/--single-dc."
    fi

    # Ensure we're in the right directory
    cd "$DVAD_HOME"

    detect_os
    install_dependencies
    check_kvm
    setup_networks
    download_windows_media
    convert_master_template
    create_vms
    wait_for_vms
    run_ansible
    finalize

    echo ""
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}   DVAD Lab Deployment Complete!                           ${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo ""
    echo "  Connect to attacker workstation:"
    echo "    ssh ws01.corp.local  OR  VNC ${CFG_VNC_BIND}:5906"
    if [ "$CFG_VNC_BIND" = "127.0.0.1" ]; then
        echo "    (VNC is loopback-only — tunnel from your laptop with:"
        echo "     ssh -L 5906:127.0.0.1:5906 user@<vps-host>)"
    fi
    echo ""
    echo "  See PLAN.md (attack-vector spec) and AGENTS.md (orientation) for lab details."
    echo "  Happy hunting!"
    echo ""
}

main "$@"
