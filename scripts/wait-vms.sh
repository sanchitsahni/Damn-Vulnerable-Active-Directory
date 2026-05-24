#!/usr/bin/env bash
# ==============================================================================
# DVAD - Wait for VM Readiness
# Polls each VM's WinRM port until all are answering or timeout expires.
# Since VMs boot from a pre-built QCOW2 (WinRM already enabled), this
# should complete within 3-5 minutes of QEMU start.
# ==============================================================================
set -euo pipefail

DVAD_HOME="${DVAD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VM_DIR="${CFG_DISK_PATH:-${DVAD_HOME}/vms}"
MAX_WAIT_MINUTES="${MAX_WAIT_MINUTES:-30}"
POLL_INTERVAL=20

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

# Static IP map (mirrors AGENTS.md topology)
declare -A VM_IPS=(
    ["dc01-corp"]="10.10.0.10"
    ["dc01-eu"]="10.10.0.11"
    ["ca01"]="10.10.0.12"
    ["file01"]="10.10.0.13"
    ["sql01"]="10.10.0.14"
    ["ws01"]="10.10.0.100"
    ["dc01-fin"]="10.20.0.10"
    ["dc01-root"]="10.30.0.10"
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

qemu_pid_alive() {
    local vm_name="$1"
    # Check pid file first
    if [ -f "${VM_DIR}/${vm_name}.pid" ]; then
        local pid
        pid=$(cat "${VM_DIR}/${vm_name}.pid" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    # Fallback: check by process name
    pgrep -f "qemu-system.*${vm_name}" &>/dev/null
}

winrm_open() {
    local ip="$1"
    nc -z -w 2 "$ip" 5985 2>/dev/null
}

# ─── Main wait loop ───────────────────────────────────────────────────────────

wait_for_all() {
    # Collect the list of VMs that have a .pid or .qcow2 in VM_DIR
    local all_vms=()
    for vm_name in "${!VM_IPS[@]}"; do
        if [ -f "${VM_DIR}/${vm_name}.qcow2" ] || [ -f "${VM_DIR}/${vm_name}.pid" ]; then
            all_vms+=("$vm_name")
        fi
    done

    if [ ${#all_vms[@]} -eq 0 ]; then
        warn "No DVAD VM disks found in ${VM_DIR}. Did create_all_vms run?"
        return 0
    fi

    local vm_count=${#all_vms[@]}
    local max_seconds=$(( MAX_WAIT_MINUTES * 60 ))
    local start_time
    start_time=$(date +%s)

    info "Waiting for $vm_count VM(s) to respond on WinRM :5985 (max ${MAX_WAIT_MINUTES} min)..."
    info "VMs: ${all_vms[*]}"

    while true; do
        local ready_count=0
        local dead_count=0

        for vm_name in "${all_vms[@]}"; do
            local ip="${VM_IPS[$vm_name]:-}"

            # Stamp .installed if QEMU is alive (disk-boot approach)
            if qemu_pid_alive "$vm_name" && [ ! -f "${VM_DIR}/${vm_name}.installed" ]; then
                touch "${VM_DIR}/${vm_name}.installed"
            fi

            if [ -z "$ip" ]; then
                ready_count=$(( ready_count + 1 ))   # no IP mapping → skip
                continue
            fi

            if winrm_open "$ip"; then
                if [ ! -f "${VM_DIR}/${vm_name}.installed" ]; then
                    touch "${VM_DIR}/${vm_name}.installed"
                    log "$vm_name ($ip) → WinRM OPEN — marked ready"
                else
                    log "$vm_name ($ip) → WinRM OPEN"
                fi
                ready_count=$(( ready_count + 1 ))
            elif ! qemu_pid_alive "$vm_name"; then
                warn "$vm_name: QEMU process not running — check ${VM_DIR}/${vm_name}.log"
                dead_count=$(( dead_count + 1 ))
                ready_count=$(( ready_count + 1 ))  # count as done (failed)
            fi
        done

        local elapsed=$(( $(date +%s) - start_time ))

        if [ "$ready_count" -ge "$vm_count" ]; then
            log "All $vm_count VM(s) processed in ${elapsed}s."
            return 0
        fi

        if [ "$elapsed" -ge "$max_seconds" ]; then
            warn "Timeout after ${MAX_WAIT_MINUTES} minutes. ${ready_count}/${vm_count} ready."
            # Force-stamp remaining so Ansible can attempt connection
            for vm_name in "${all_vms[@]}"; do
                touch "${VM_DIR}/${vm_name}.installed" 2>/dev/null || true
            done
            return 0
        fi

        local remaining=$(( max_seconds - elapsed ))
        info "Progress: ${ready_count}/${vm_count} ready | elapsed ${elapsed}s | ${remaining}s remaining"
        sleep "$POLL_INTERVAL"
    done
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    wait_for_all
fi
