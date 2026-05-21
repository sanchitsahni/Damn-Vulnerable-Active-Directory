#!/usr/bin/env bash
set -euo pipefail
# setup-deps.sh : Detect OS and install QEMU/KVM, Ansible, dnsmasq, bridge-utils

RCol='\033[0m' ; Gre='\033[0;32m' ; Yel='\033[1;33m' ; Red='\033[0;31m'
log(){ echo -e "${Gre}[SETUP]${RCol} $*"; }
warn(){ echo -e "${Yel}[WARN]${RCol} $*"; }
die(){ echo -e "${Red}[ERR]${RCol} $*"; exit 1; }

detect_os(){
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VER=${VERSION_ID:-unknown}
    else
        die "Cannot detect OS. /etc/os-release missing."
    fi
}

install_debian_ubuntu(){
    log "Detected Debian/Ubuntu ($OS_VER)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
        bridge-utils dnsmasq net-tools iptables nftables \
        genisoimage aria2 curl wget python3-pip python3-venv \
        winbind cifs-utils samba smbclient jq
    pip3 install ansible pywinrm --quiet
    systemctl enable --now libvirtd 2>/dev/null || true
}

install_fedora_rhel(){
    log "Detected Fedora/RHEL ($OS_VER)"
    dnf install -y -q \
        qemu-kvm qemu-img libvirt libvirt-client \
        bridge-utils dnsmasq net-tools iptables-nft \
        genisoimage aria2 curl wget python3-pip \
        winbind cifs-utils samba samba-client jq
    pip3 install ansible pywinrm --quiet
    systemctl enable --now libvirtd 2>/dev/null || true
}

install_arch(){
    log "Detected Arch Linux"
    pacman -Sy --noconfirm --needed \
        qemu-full dnsmasq bridge-utils iptables-nft openresolv \
        cdrtools aria2 curl wget python-pip \
        samba jq libvirt
    pip install ansible pywinrm --quiet
    systemctl enable --now libvirtd 2>/dev/null || true
}

install_opensuse(){
    log "Detected openSUSE"
    zypper -n install -y \
        qemu-kvm qemu-tools libvirt bridge-utils \
        dnsmasq iptables cdrtools aria2 curl wget \
        python3-pip samba winbind jq
    pip3 install ansible pywinrm --quiet
    systemctl enable --now libvirtd 2>/dev/null || true
}

check_kvm(){
    if [ ! -c /dev/kvm ]; then
        warn "/dev/kvm not present. VMs will be extremely slow."
        warn "Enable VT-x/AMD-V in BIOS and add user to kvm/libvirt groups."
    else
        log "KVM acceleration available."
    fi
}

main(){
    log "Starting dependency installation..."
    detect_os
    case "$OS_ID" in
        debian|ubuntu|pop) install_debian_ubuntu ;;
        fedora|rhel|centos|rocky|almalinux) install_fedora_rhel ;;
        arch|manjaro) install_arch ;;
        opensuse-leap|opensuse-tumbleweed) install_opensuse ;;
        *) die "Unsupported OS: $OS_ID. Add to setup-deps.sh manually." ;;
    esac
    check_kvm
    log "All dependencies installed. Run ./download-windows.sh next."
}
main "$@"
