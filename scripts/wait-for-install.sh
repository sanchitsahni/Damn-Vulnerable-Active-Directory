#!/usr/bin/env bash
set -uo pipefail
# wait-for-install.sh : Poll VMs for WinRM availability after install

TARGETS=(
    "10.10.0.10:5985"
    "10.10.0.11:5985"
    "10.10.0.12:5985"
    "10.10.0.13:5985"
    "10.10.0.14:5985"
    "10.10.0.100:5985"
    "10.20.0.10:5985"
    "10.30.0.10:5985"
)

log(){ echo "[WAIT] $*"; }

wait_for_winrm(){
    local max_wait=1800  # 30 minutes
    local elapsed=0
    local all_up=0
    while [ "$all_up" -lt ${#TARGETS[@]} ] && [ "$elapsed" -lt "$max_wait" ]; do
        all_up=0
        for t in "${TARGETS[@]}"; do
            if timeout 2 bash -c "echo >/dev/tcp/${t%:*}/${t#*:}" 2>/dev/null; then
                all_up=$((all_up + 1))
            fi
        done
        log "WinRM reachable on $all_up/${#TARGETS[@]} hosts... (${elapsed}s elapsed)"
        if [ "$all_up" -eq ${#TARGETS[@]} ]; then
            log "All VMs ready for Ansible."
            return 0
        fi
        sleep 15
        elapsed=$((elapsed + 15))
    done
    log "TIMEOUT: Not all VMs came online. Check QEMU logs."
    exit 1
}

main(){ wait_for_winrm; }
main "$@"
