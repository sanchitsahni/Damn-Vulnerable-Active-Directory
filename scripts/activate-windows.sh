#!/usr/bin/env bash
# ==============================================================================
# DVAD - Massgrave Windows Activation
# ==============================================================================
set -euo pipefail

DVAD_HOME="${DVAD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VM_DIR="${CFG_DISK_PATH:-${DVAD_HOME}/vms}"

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

# Generate activation PowerShell script
generate_activation_script() {
    cat << 'MGSCRIPT'
<#
.SYNOPSIS
DVAD Windows Activation via Massgrave
#>
$ErrorActionPreference = "Continue"

Write-Host "=== DVAD Activation Starting ==="

# Disable IE first run wizard
$null = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue

# Massgrave HWID activation
Write-Host "Downloading and running Massgrave activation..."
try {
    $script = Invoke-RestMethod -Uri "https://massgrave.dev/get" -UseBasicParsing -ErrorAction Stop
    Invoke-Expression $script
    Write-Host "Massgrave activation completed."
} catch {
    Write-Host "Massgrave download failed. Trying alternative..."
    try {
        # Alternative: direct HWID script
        irm https://get.activated.win | iex
    } catch {
        Write-Host "All activation methods failed. Lab will use evaluation period."
    }
}

# Create activation success marker
New-Item -ItemType File -Path "C:\dvad-activated.txt" -Force

Write-Host "=== DVAD Activation Complete ==="
MGSCRIPT
}

# Send activation script to a VM via QEMU guest exec or file injection
activate_vm() {
    local vm_name="$1"
    local vnc="$2"

    if [ -f "${VM_DIR}/${vm_name}.activated" ]; then
        info "$vm_name already activated."
        return 0
    fi

    info "Activating $vm_name..."

    # Write activation script to a share the VM can access
    # Since VMs are isolated, we use the approach of injecting via QEMU guest agent or CD-ROM

    local activation_dir="${VM_DIR}/activation"
    mkdir -p "$activation_dir"

    # Generate the script
    generate_activation_script > "${activation_dir}/activate.ps1"

    # Create ISO with activation script
    local iso_path="${activation_dir}/${vm_name}-activate.iso"
    local iso_dir="/tmp/dvad-activate-${vm_name}"
    mkdir -p "$iso_dir"
    cp "${activation_dir}/activate.ps1" "$iso_dir/activate.ps1"

    if command -v genisoimage &>/dev/null; then
        genisoimage -quiet -J -r -o "$iso_path" "$iso_dir" 2>/dev/null
    elif command -v mkisofs &>/dev/null; then
        mkisofs -quiet -J -r -o "$iso_path" "$iso_dir" 2>/dev/null
    else
        warn "Cannot create ISO for activation script."
        rm -rf "$iso_dir"
        return 1
    fi
    rm -rf "$iso_dir"

    # Attach ISO via QEMU monitor and run script
    if [ -f "${VM_DIR}/${vm_name}.mon" ]; then
        # Add CDROM with activation script
        echo "change ide1-cd0 ${iso_path}" | nc -U "${VM_DIR}/${vm_name}.mon" 2>/dev/null || true
        sleep 2
        # Send key sequence to run PowerShell
        # Note: This requires the VM to have WinRM or an interactive session
        # In practice, activation happens via WinRM in the Ansible phase
    fi

    # Mark as pending activation (actual activation happens via Ansible WinRM)
    touch "${VM_DIR}/${vm_name}.pending-activation"
    info "$vm_name: Activation script ready. Will be executed via WinRM."
}

activate_all() {
    info "Preparing Windows activation for all VMs..."

    for vm_dir in "${VM_DIR}"/*/; do
        [ -d "$vm_dir" ] || continue
    done

    # Generate activation script for each VM
    local activation_dir="${VM_DIR}/activation"
    mkdir -p "$activation_dir"
    generate_activation_script > "${activation_dir}/activate.ps1"

    for installed_file in "${VM_DIR}"/*.installed; do
        [ -f "$installed_file" ] || continue
        local vm_name
        vm_name=$(basename "$installed_file" .installed)
        local vnc=""

        # Don't re-activate
        if [ -f "${VM_DIR}/${vm_name}.activated" ]; then
            continue
        fi

        activate_vm "$vm_name" "$vnc"
    done

    log "Activation scripts prepared. These will execute via Ansible WinRM."
    log "If activation is needed immediately, run the scripts via VNC console."
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    activate_all
fi
