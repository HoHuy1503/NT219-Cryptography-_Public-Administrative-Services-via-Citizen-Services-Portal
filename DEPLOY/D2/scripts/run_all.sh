#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D2_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$D2_DIR"

echo '=== STEP 1: Provision VMs with Vagrant ==='
vagrant up --provision

echo '=== STEP 2: Apply Ansible playbook ==='
ansible-playbook -i playbook/inventory/hosts.yml playbook/site.yml -v

echo '=== STEP 3: Run mTLS and failover checks ==='
bash "$SCRIPT_DIR/test_mtls_and_failover.sh"

echo '=== DONE: D2 completed successfully ==='