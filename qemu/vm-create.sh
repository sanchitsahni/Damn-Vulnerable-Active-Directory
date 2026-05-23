#!/usr/bin/env bash
# ==============================================================================
# DVAD VM Creation - QEMU Virtual Machine Definition & Launch
# ==============================================================================
set -euo pipefail

DVAD_HOME="${DVAD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MEDIA_DIR="${DVAD_HOME}/media"
VM_DIR="${CFG_DISK_PATH:-${DVAD_HOME}/vms}"
AUTOUNATTEND_DIR="${DVAD_HOME}/autounattend"
ISO_FILE="${MEDIA_DIR}/windows-server-2022-eval.iso"
VIRTIO_ISO="${MEDIA_DIR}/virtio-win.iso"

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

# KVM_OPT carries the -enable-kvm flag; ACCEL is the value for -machine accel=
if [ -e /dev/kvm ]; then
    KVM_OPT="${KVM_OPT:--enable-kvm}"
    ACCEL="kvm"
else
    warn "No KVM available. Using software emulation (very slow)."
    KVM_OPT=""
    ACCEL="tcg"
fi

# VPS mode strips display devices (no GUI host) and forces VNC to loopback by default.
VPS_MODE="${CFG_VPS_MODE:-0}"
VNC_BIND="${CFG_VNC_BIND:-127.0.0.1}"

# ==============================================================================
# VM Definitions
# ==============================================================================
# Format: name,hostname,mac,ram_mb,disk_gb,vcpus,vnc_display,bridge,nic_model
# vnc_display N → VNC listens on port 5900+N (so display 1 = port 5901).
declare -A VM_DEFS

VM_DEFS=(
    # corp.local domain VMs
    ["dc01-corp"]="dc01.corp.local|52:54:00:00:01:01|2048|40|2|1|dvad-ctf|e1000e"
    ["dc01-eu"]="dc01.eu.corp.local|52:54:00:00:01:02|2048|25|2|2|dvad-ctf|e1000e"
    ["ca01"]="ca01.corp.local|52:54:00:00:01:03|2048|25|2|3|dvad-ctf|e1000e"
    ["file01"]="file01.corp.local|52:54:00:00:01:04|1536|20|2|4|dvad-ctf|e1000e"
    ["sql01"]="sql01.corp.local|52:54:00:00:01:05|2048|25|2|5|dvad-ctf|e1000e"
    ["ws01"]="ws01.corp.local|52:54:00:00:01:06|1024|30|2|6|dvad-ctf|e1000e"
    # finance.local domain
    ["dc01-fin"]="dc01.finance.local|52:54:00:00:02:01|2048|25|2|7|dvad-finance|e1000e"
    # root.corp domain
    ["dc01-root"]="dc01.root.corp|52:54:00:00:03:01|2048|25|2|8|dvad-root|e1000e"
)

# Scale per-VM RAM/CPU to fit a target budget. Called once before launch.
# Reads: CFG_MEM_TOTAL (GB), CFG_CPU_TOTAL (vCPUs).
scale_vm_defs() {
    local target_mem_mb=0 target_cpus=0
    [ -n "${CFG_MEM_TOTAL:-}" ] && target_mem_mb=$(( CFG_MEM_TOTAL * 1024 ))
    [ -n "${CFG_CPU_TOTAL:-}" ] && target_cpus="$CFG_CPU_TOTAL"
    [ "$target_mem_mb" -eq 0 ] && [ "$target_cpus" -eq 0 ] && return 0

    # Sum current allocations to derive a scale factor.
    local sum_mem=0 sum_cpu=0
    for def in "${VM_DEFS[@]}"; do
        IFS='|' read -r _h _m ram _d cpu _v _b _n <<< "$def"
        sum_mem=$(( sum_mem + ram ))
        sum_cpu=$(( sum_cpu + cpu ))
    done

    local key def host mac ram disk cpu vnc bridge nic new_ram new_cpu
    for key in "${!VM_DEFS[@]}"; do
        def="${VM_DEFS[$key]}"
        IFS='|' read -r host mac ram disk cpu vnc bridge nic <<< "$def"
        new_ram="$ram"
        new_cpu="$cpu"
        if [ "$target_mem_mb" -gt 0 ] && [ "$sum_mem" -gt 0 ]; then
            new_ram=$(( ram * target_mem_mb / sum_mem ))
            [ "$new_ram" -lt 1024 ] && new_ram=1024
        fi
        if [ "$target_cpus" -gt 0 ] && [ "$sum_cpu" -gt 0 ]; then
            new_cpu=$(( cpu * target_cpus / sum_cpu ))
            [ "$new_cpu" -lt 1 ] && new_cpu=1
        fi
        VM_DEFS[$key]="${host}|${mac}|${new_ram}|${disk}|${new_cpu}|${vnc}|${bridge}|${nic}"
    done
    log "Scaled VM sizing: target=${CFG_MEM_TOTAL:-?}GB RAM, ${CFG_CPU_TOTAL:-?} vCPUs total"
}

# ==============================================================================
# Autounattend generation
# ==============================================================================
generate_autounattend() {
    local hostname="$1"
    local vm_name="$2"
    local output_dir="${AUTOUNATTEND_DIR}/${vm_name}"
    mkdir -p "$output_dir"

    local admin_password="DVADlab2024!"    # Generate unattend.xml for OOBE configuration of the pre-installed VHD
    cat > "${output_dir}/unattend.xml" << AUTOXML
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="specialize">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>${hostname%%.*}</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>powershell.exe -NoProfile -Command "Set-ExecutionPolicy Bypass -Scope LocalMachine -Force"</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>${admin_password}</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <RegisteredOwner>DVAD</RegisteredOwner>
            <RegisteredOrganization>DVAD Lab</RegisteredOrganization>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>cmd.exe /c "for %i in (C D E F G H I) do if exist %i:\post-install.ps1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File %i:\post-install.ps1"</CommandLine>
                    <Description>DVAD Post-Install Script</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
AUTOXML

    # Generate post-install PowerShell script
    cat > "${output_dir}/post-install.ps1" << 'PSCRIPT'
# DVAD Post-Install Setup Script
$ErrorActionPreference = "Continue"
Start-Transcript -Path "C:\dvad-install.log" -Append

Write-Host "=== DVAD Post-Install Starting ==="

# Disable Windows Defender and security features for lab
Write-Host "Disabling Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue

# Disable Windows Firewall
Write-Host "Disabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
netsh advfirewall set allprofiles state off

# Disable UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0

# Enable Remote Desktop
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0

# Enable WinRM
winrm quickconfig -force
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Enable RDP Restricted Admin mode (for Pass-the-Hash RDP)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWORD -Force

# Create DVAD directory
New-Item -ItemType Directory -Path "C:\DVAD" -Force
New-Item -ItemType Directory -Path "C:\DVAD\tools" -Force
New-Item -ItemType Directory -Path "C:\DVAD\flags" -Force

# Set execution policy
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force

# Enable SMB1 for legacy (vulnerable!)
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

# Configure time
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time

# Disable Windows Update
Stop-Service wuauserv -Force
Set-Service wuauserv -StartupType Disabled

# Disable IPv6 if not needed (reduces noise)
# Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding -ComponentID ms_tcpip6

Write-Host "=== DVAD Post-Install Complete ==="
Stop-Transcript

# Signal completion
New-Item -ItemType File -Path "C:\dvad-ready.txt" -Force
PSCRIPT

    # Return the directory path to be used as vvfat
    echo "$output_dir"
}

# ==============================================================================
# QEMU Disk Creation
# ==============================================================================
create_disk() {
    local vm_name="$1"
    local size_gb="$2"
    local disk_path="${VM_DIR}/${vm_name}.qcow2"
    local base_qcow2="${MEDIA_DIR}/win2k25.qcow2"

    if [ -f "$disk_path" ]; then
        info "Disk exists for $vm_name: $(du -h "$disk_path" | cut -f1)"
        return 0
    fi

    mkdir -p "$VM_DIR"
    log "Creating linked clone for $vm_name (${size_gb}GB)..."
    qemu-img create -f qcow2 -b "$base_qcow2" -F qcow2 "$disk_path" "${size_gb}G"
}

# ==============================================================================
# QEMU VM Launch
# ==============================================================================
launch_vm() {
    local vm_name="$1"
    local hostname="$2"
    local mac="$3"
    local ram_mb="$4"
    local vcpus="$6"
    local vnc_display="$7"
    local bridge="$8"
    local nic_model="$9"

    local disk_path="${VM_DIR}/${vm_name}.qcow2"
    local auto_iso="${AUTOUNATTEND_DIR}/${vm_name}/autounattend-${vm_name}.iso"
    local vnc_arg="${VNC_BIND}:${vnc_display}"
    local vnc_port=$(( 5900 + vnc_display ))

    # Display args differ between desktop and VPS profiles.
    local DISPLAY_ARGS=()
    if [ "$VPS_MODE" = "1" ]; then
        DISPLAY_ARGS=(-display none -vnc "$vnc_arg" -vga std)
    else
        DISPLAY_ARGS=(-vnc "$vnc_arg" -vga qxl -usb -device usb-tablet)
    fi

    # Check if VM is already running
    if pgrep -f "qemu-system.*${vm_name}" &>/dev/null; then
        info "VM $vm_name is already running."
        return 0
    fi

    # Check if VM is already installed (disk exists and we can check readiness)
    if [ -f "${VM_DIR}/${vm_name}.installed" ]; then
        info "VM $vm_name already installed. Starting normally..."

        # Start VM without install media
        qemu-system-x86_64 \
            -name "$vm_name" \
            -machine "q35,accel=${ACCEL}" \
            ${KVM_OPT} \
            -cpu host \
            -smp "cpus=${vcpus}" \
            -m "${ram_mb}M" \
            -drive "file=${disk_path},if=none,id=drive0,format=qcow2,cache=writeback" \
            -device "virtio-blk-pci,drive=drive0,bootindex=1" \
            -netdev "bridge,id=net0,br=${bridge}" \
            -device "${nic_model}-net-pci,netdev=net0,mac=${mac}" \
            "${DISPLAY_ARGS[@]}" \
            -device virtio-balloon-pci \
            -rtc base=localtime \
            -daemonize \
            -pidfile "${VM_DIR}/${vm_name}.pid" \
            -monitor "unix:${VM_DIR}/${vm_name}.mon,server,nowait" 2>/dev/null &

        return 0
    fi

    log "Launching $vm_name ($hostname) - VNC: ${vnc_arg} (port ${vnc_port})"

    # Build QEMU command
    local QEMU_CMD=(
        qemu-system-x86_64
        -name "$vm_name"
        -machine "q35,accel=${ACCEL}"
        ${KVM_OPT}
        -cpu host
        -smp "cpus=${vcpus}"
        -m "${ram_mb}M"
        # Boot disk (using IDE native for VHD compatibility)
        -drive "file=${disk_path},if=none,id=drive0,format=qcow2,cache=writeback"
        -device "ide-hd,drive=drive0,bus=ide.0,bootindex=1"
        # VirtIO drivers ISO
        -drive "file=${VIRTIO_ISO},if=none,id=cdrom1,media=cdrom"
        -device "ide-cd,drive=cdrom1,bus=ide.1,bootindex=3"
    )

    # Autounattend directory if available
    if [ -d "$auto_iso" ]; then
        QEMU_CMD+=(
            -drive "file=fat:ro:${auto_iso},if=none,id=auto_drive,format=raw"
            -device "ide-hd,drive=auto_drive,bus=ide.2"
        )
    fi

    local nic_device="${nic_model}"
    if [ "$nic_model" = "virtio" ]; then
        nic_device="virtio-net-pci"
    fi

    QEMU_CMD+=(
        # Network
        -netdev "bridge,id=net0,br=${bridge}"
        -device "${nic_device},netdev=net0,mac=${mac}"
        # Display & VNC (varies by profile)
        "${DISPLAY_ARGS[@]}"
        # Devices
        -device virtio-balloon-pci
        -rtc base=localtime
        # Boot order
        -boot "order=dc,menu=on"
        # Daemonize
        -daemonize
        -pidfile "${VM_DIR}/${vm_name}.pid"
        -monitor "unix:${VM_DIR}/${vm_name}.mon,server,nowait"
    )

    "${QEMU_CMD[@]}" 2>"${VM_DIR}/${vm_name}.log" &

    sleep 2

    if [ -f "${VM_DIR}/${vm_name}.pid" ]; then
        log "$vm_name started (PID: $(cat ${VM_DIR}/${vm_name}.pid))"
    else
        warn "$vm_name may have failed to start. Check ${VM_DIR}/${vm_name}.log"
    fi
}

# ==============================================================================
# Parse VM definition
# ==============================================================================
parse_vm_def() {
    # Returns: hostname|mac|ram|disk|vcpus|vnc|bridge|nic
    local def="${VM_DEFS[$1]}"
    IFS='|' read -r hostname mac ram disk vcpus vnc bridge nic <<< "$def"
}

# ==============================================================================
# Create all VMs
# ==============================================================================
create_all_vms() {
    mkdir -p "$VM_DIR"

    local DEPLOY_MODE="${CFG_DEPLOY_MODE:-full}"

    # Apply user-supplied RAM/CPU budget by scaling VM_DEFS in place.
    scale_vm_defs

    # Filter VMs based on deploy mode
    local VMS_TO_DEPLOY=()
    case "$DEPLOY_MODE" in
        single-dc)
            VMS_TO_DEPLOY=("dc01-corp")
            ;;
        minimal)
            VMS_TO_DEPLOY=("dc01-corp" "ca01" "file01" "sql01" "ws01")
            ;;
        full|*)
            VMS_TO_DEPLOY=("${!VM_DEFS[@]}")
            ;;
    esac

    log "Deploy mode: $DEPLOY_MODE"
    log "VMs to deploy: ${VMS_TO_DEPLOY[*]}"

    for vm_name in "${VMS_TO_DEPLOY[@]}"; do
        parse_vm_def "$vm_name"
        info "=== VM: $vm_name ($hostname) ==="

        # Generate autounattend
        local auto_iso
        auto_iso=$(generate_autounattend "$hostname" "$vm_name")
        info "  Autounattend: $auto_iso"

        # Create disk
        create_disk "$vm_name" "$disk"

        # Launch VM
        launch_vm "$vm_name" "$hostname" "$mac" "$ram" "$disk" "$vcpus" "$vnc" "$bridge" "$nic"
    done

    echo ""
    log "All VMs launched. VNC endpoints:"
    for vm_name in "${VMS_TO_DEPLOY[@]}"; do
        parse_vm_def "$vm_name"
        echo "  $vm_name ($hostname) -> ${VNC_BIND}:$(( 5900 + vnc ))"
    done
    echo ""
    log "Windows installation will proceed automatically (~20-30 minutes per VM)."
    log "Monitor with: watch -n 30 'ls $VM_DIR/*.installed 2>/dev/null'"
}

# ==============================================================================
# VM Management
# ==============================================================================
stop_vm() {
    local vm_name="$1"
    if [ -f "${VM_DIR}/${vm_name}.pid" ]; then
        local pid=$(cat "${VM_DIR}/${vm_name}.pid")
        log "Stopping $vm_name (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
        kill -9 "$pid" 2>/dev/null || true
        rm -f "${VM_DIR}/${vm_name}.pid"
    else
        warn "No PID file for $vm_name"
    fi
}

status_vms() {
    echo "=== DVAD VM Status ==="
    for vm_name in "${!VM_DEFS[@]}"; do
        if [ -f "${VM_DIR}/${vm_name}.pid" ] && kill -0 "$(cat "${VM_DIR}/${vm_name}.pid")" 2>/dev/null; then
            echo "  $vm_name: RUNNING (PID: $(cat ${VM_DIR}/${vm_name}.pid))"
        elif [ -f "${VM_DIR}/${vm_name}.installed" ]; then
            echo "  $vm_name: STOPPED (installed)"
        else
            echo "  $vm_name: STOPPED"
        fi
    done
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DVAD_HOME="$(cd "$SCRIPT_DIR/.." && pwd)"

    log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
    warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
    info() { echo -e "\033[0;34m[*]\033[0m $*"; }

    case "${1:-create}" in
        create)   create_all_vms ;;
        stop)     stop_vm "${2:-}" ;;
        status)   status_vms ;;
        destroy)
            warn "Destroying all VMs..."
            for vm_name in "${!VM_DEFS[@]}"; do
                stop_vm "$vm_name"
            done
            rm -rf "$VM_DIR"
            log "All VMs destroyed."
            ;;
        *) echo "Usage: $0 [create|stop <name>|status|destroy]" ;;
    esac
fi
