# RUNBOOK.md — Huong Dan Chay Tu May Sach
## NT219 Topic 11 | Thoi gian uoc tinh: 30-45 phut

## Yeu cau
- WSL2 + Ubuntu 22.04 (khuyen nghi cho Windows)
- RAM >= 8GB, Disk >= 20GB
- Docker 24+, docker compose v2, git, jq, python3, pip3
- Vault CLI 1.16+

## D1 — Docker Compose

### Buoc 1: Clone repo
git clone <REPO_URL> NT219-Topic11
cd NT219-Topic11

### Buoc 2: Chuan bi bien moi truong
cp DEPLOY/D1/.env.example DEPLOY/D1/.env

### Buoc 3: Khoi dong stack
cd DEPLOY/D1
docker compose up -d
echo "Cho 25-40 giay cho Keycloak/Vault khoi dong"
sleep 30

### Buoc 4: Bootstrap Vault
bash scripts/bootstrap_vault.sh

### Buoc 5: Seed Keycloak data
bash scripts/seed_test_data.sh

### Buoc 6: Smoke test
bash scripts/smoke_test.sh

### Buoc 7: Demo nhanh 4 buoc I/O
bash scripts/demo_e2e.sh

## Offline QR verify (tu chon)
- Neu can verify offline QR payload, set QR_FERNET_KEY trong DEPLOY/D1/.env truoc khi docker compose up.
- Sau khi tao QR, chay:
python3 DEPLOY/D1/scripts/verify_qr_offline.py --qr "<qr_data>" --key "$QR_FERNET_KEY"

## Chay toan bo Evaluation (9 bai)
cd EVAL
bash run_all_evals.sh

Ket qua luu tai:
- EVAL/E-C/*.json
- EVAL/E-N/*.json
- EVAL/E-Z/*.json
- EVAL/E-X/*.json

Bang chung luu tai:
- EVIDENCE/pcaps
- EVIDENCE/logs

## D2 — Vagrant + Ansible

### Yeu cau bo sung
- VirtualBox 7+
- Vagrant 2.3+
- Ansible 2.14+

### Trien khai
cd DEPLOY/D2
vagrant up --provision
ansible-playbook -i playbook/inventory/hosts.yml playbook/site.yml -v
bash scripts/test_mtls_and_failover.sh

## Loi thuong gap
- Keycloak chua san sang: doi them 30-60 giay roi chay lai seed script.
- Vault sealed sau restart: unseal bang key trong /root/vault-init.json.
- Port bi trung: docker compose down va giai phong cong 5000/5002/8080/8181/8200/8443.
