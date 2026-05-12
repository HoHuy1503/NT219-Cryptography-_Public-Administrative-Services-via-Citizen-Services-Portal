#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D2_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$D2_DIR"

VAGRANT_BIN="vagrant"
if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
	export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1
	if command -v vagrant.exe >/dev/null 2>&1; then
		VAGRANT_BIN="vagrant.exe"
	elif [ -x "/mnt/c/HashiCorp/Vagrant/bin/vagrant.exe" ]; then
		VAGRANT_BIN="/mnt/c/HashiCorp/Vagrant/bin/vagrant.exe"
	else
		echo 'WSL detected but Windows Vagrant was not found.'
		echo 'Install Vagrant on Windows or add vagrant.exe to PATH, then rerun.'
		exit 1
	fi
fi

echo '=== STEP 1: Provision VMs with Vagrant ==='
"$VAGRANT_BIN" up --provision

echo '=== STEP 2: Apply Ansible playbook ==='
ansible-playbook -i playbook/inventory/hosts.yml playbook/site.yml -v

echo '=== STEP 3: Run mTLS and failover checks ==='
bash "$SCRIPT_DIR/test_mtls_and_failover.sh"

echo '=== DONE: D2 completed successfully ==='