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

    local ip=""
    case "$vm_name" in
        "dc01-corp") ip="10.10.0.10" ;;
        "dc01-eu")   ip="10.10.0.11" ;;
        "ca01")      ip="10.10.0.12" ;;
        "file01")    ip="10.10.0.13" ;;
        "sql01")     ip="10.10.0.14" ;;
        "ws01")      ip="10.10.0.100" ;;
        "dc01-fin")  ip="10.20.0.10" ;;
        "dc01-root") ip="10.30.0.10" ;;
    esac

    if [ -n "$ip" ]; then
        if nc -z -w 2 "$ip" 5985 2>/dev/null; then
            info "$vm_name ($ip): WinRM port 5985 is OPEN! VM is ready."
            return 0
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
