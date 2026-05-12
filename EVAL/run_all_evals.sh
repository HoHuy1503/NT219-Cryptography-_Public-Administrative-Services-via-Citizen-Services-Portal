#!/bin/bash
set -e

echo '======================================'
echo '  CHẠY TOÀN BỘ EVALUATION (9 bài)  '
echo '======================================'

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo '=== START D1 STACK ==='
cd "$ROOT_DIR/DEPLOY/D1"
docker compose up -d --build >/dev/null
sleep 45
set -a
source .env
set +a
bash scripts/bootstrap_vault.sh >/dev/null
bash scripts/seed_test_data.sh >/dev/null
cd "$ROOT_DIR"

bash "$ROOT_DIR/EVAL/E-C/run_e_c1.sh"
python3 "$ROOT_DIR/EVAL/E-C/run_e_c2.py"
python3 "$ROOT_DIR/EVAL/E-C/run_e_c3.py"
python3 "$ROOT_DIR/EVAL/E-N/run_e_n1.py"
python3 "$ROOT_DIR/EVAL/E-N/run_e_n2.py"
python3 "$ROOT_DIR/EVAL/E-Z/run_e_z1.py"
python3 "$ROOT_DIR/EVAL/E-Z/run_e_z2.py"
bash "$ROOT_DIR/EVAL/E-X/run_e_x1.sh"
python3 "$ROOT_DIR/EVAL/E-X/run_e_x2.py"

echo ''
echo '=== KẾT QUẢ TỔNG HỢP ==='

for f in "$ROOT_DIR"/EVAL/E-C/*.json \
         "$ROOT_DIR"/EVAL/E-N/*.json \
         "$ROOT_DIR"/EVAL/E-Z/*.json \
         "$ROOT_DIR"/EVAL/E-X/*.json
do
  ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("eval_id", ""))' "$f")
  STATUS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", ""))' "$f")
  echo "  $ID: $STATUS"
done
