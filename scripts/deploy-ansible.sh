#!/usr/bin/env bash
set -euo pipefail
# deploy-ansible.sh : Run Ansible playbooks after VMs are up

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANSIBLE_DIR="$BASE_DIR/ansible"

log(){ echo "[ANSIBLE] $*"; }

main(){
    cd "$ANSIBLE_DIR"
    log "Installing Ansible collections..."
    ansible-galaxy collection install community.windows ansible.windows --force 2>/dev/null || true

    log "Running site.yml - this will take ~20 minutes..."
    ansible-playbook -i inventory/hosts.yml playbooks/site.yml \
        -e "ansible_winrm_server_cert_validation=ignore" \
        -e "ansible_winrm_transport=basic" \
        --timeout 120

    log "Ansible provisioning complete."
}
main "$@"
