#!/usr/bin/env bash
# ==============================================================================
# DVAD - Wait for VM Readiness
# Polls VMs until Windows installation completes
# ==============================================================================
set -euo pipefail

DVAD_HOME="${DVAD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VM_DIR="${CFG_DISK_PATH:-${DVAD_HOME}/vms}"
MAX_WAIT_MINUTES=45
POLL_INTERVAL=60

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

check_vm_ready() {
    local vm_name="$1"
    local vnc_port="$2"

    # Mark as installed if we've already done so
    if [ -f "${VM_DIR}/${vm_name}.installed" ]; then
        return 0
    fi

    # Check if VM is running
    if ! [ -f "${VM_DIR}/${vm_name}.pid" ]; then
        warn "$vm_name: No PID file. VM not running."
        return 1
    fi

    local pid
    pid=$(cat "${VM_DIR}/${vm_name}.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        warn "$vm_name: Process $pid not found. VM may have crashed."
        return 1
    fi

    # Try to detect if Windows is ready
    # Use QEMU monitor to send a guest agent ping (if agent is installed)
    # Fallback: poll for the dvad-ready signal via the installation flag approach

    # We check if the VM has been up long enough and has a disk with data
    # After max wait, we assume it's ready if the VM is still running
    local disk_path="${VM_DIR}/${vm_name}.qcow2"
    if [ -f "$disk_path" ]; then
        local disk_size
        disk_size=$(stat -c%s "$disk_path" 2>/dev/null || echo 0)
        # If disk has been written to (more than 5GB), assume installation is progressing
        if [ "$disk_size" -gt 5000000000 ]; then
            # Check uptime from process (simple heuristic)
            local proc_start
            proc_start=$(stat -c%Y "/proc/$pid" 2>/dev/null || echo 0)
            local now
            now=$(date +%s)
            local uptime_seconds=$((now - proc_start))

            if [ "$uptime_seconds" -gt 600 ]; then  # 10 minutes minimum
                info "$vm_name: Disk populated ($(numfmt --to=iec $disk_size)), been up ${uptime_seconds}s"
                return 0
            fi
        fi
    fi

    return 1
}

wait_for_all() {
    local vm_count=0
    local ready_count=0

    # Count VMs
    for pidfile in "${VM_DIR}"/*.pid; do
        [ -f "$pidfile" ] || continue
        vm_count=$((vm_count + 1))
    done

    if [ "$vm_count" -eq 0 ]; then
        warn "No running VMs found in ${VM_DIR}"
        return 0
    fi

    info "Waiting for $vm_count VMs to complete Windows installation..."
    info "This can take 20-45 minutes depending on hardware."
    info ""

    local start_time
    start_time=$(date +%s)
    local max_seconds=$((MAX_WAIT_MINUTES * 60))

    while true; do
        ready_count=0

        for pidfile in "${VM_DIR}"/*.pid; do
            [ -f "$pidfile" ] || continue
            local vm_name
            vm_name=$(basename "$pidfile" .pid)
            local vnc=""

            if check_vm_ready "$vm_name" "$vnc"; then
                ready_count=$((ready_count + 1))
                if ! [ -f "${VM_DIR}/${vm_name}.installed" ]; then
                    touch "${VM_DIR}/${vm_name}.installed"
                    log "$vm_name -> READY"
                fi
            fi
        done

        local elapsed
        elapsed=$(($(date +%s) - start_time))

        if [ "$ready_count" -ge "$vm_count" ]; then
            log "All $vm_count VMs are ready! (${elapsed}s elapsed)"
            return 0
        fi

        if [ "$elapsed" -ge "$max_seconds" ]; then
            warn "Timeout after ${MAX_WAIT_MINUTES} minutes."
            warn "Ready: $ready_count / $vm_count VMs."
            warn "Continuing with available VMs. Some may not be fully installed."
            for pidfile in "${VM_DIR}"/*.pid; do
                [ -f "$pidfile" ] || continue
                local vm_name
                vm_name=$(basename "$pidfile" .pid)
                touch "${VM_DIR}/${vm_name}.installed"
            done
            return 0
        fi

        # Progress display
        info "Waiting... ${ready_count}/${vm_count} ready (${elapsed}s / ${max_seconds}s)"
        sleep "$POLL_INTERVAL"
    done
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    wait_for_all
fi
