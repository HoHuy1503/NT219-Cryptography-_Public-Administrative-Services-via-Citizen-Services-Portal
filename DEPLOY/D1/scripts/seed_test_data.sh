#!/bin/bash
# DEPLOY/D1/scripts/seed_test_data.sh
set -euo pipefail

KC_URL="http://localhost:8080"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-AdminPass@2024}"
KC_ADMIN_PASS="${KC_ADMIN_PASS//$'\r'/}"
 
# Lấy admin token (retry đến khi Keycloak sẵn sàng)
ADMIN_TOKEN=""
for _ in $(seq 1 30); do
  RAW_TOKEN_RESP=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli&grant_type=password" \
    -d "username=admin&password=${KC_ADMIN_PASS}" || true)

  ADMIN_TOKEN=$(printf '%s' "$RAW_TOKEN_RESP" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("access_token", ""))
except Exception:
    print("")' 2>/dev/null || true)

  if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
    break
  fi
  sleep 2
done

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Cannot obtain Keycloak admin token. Check KC_ADMIN_PASS and Keycloak readiness."
  exit 1
fi
 
create_user() {
  local username=$1 email=$2 password=$3 role=$4 dept=$5
  local user_id
  user_id=$(curl -s "$KC_URL/admin/realms/govportal/users?username=$username" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d[0].get("id", "") if d else ""))')

  if [ -z "$user_id" ]; then
    user_id=$(curl -s -X POST "$KC_URL/admin/realms/govportal/users" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$username\",\"email\":\"$email\",
           \"enabled\":true,\"attributes\":{\"dept\":[\"$dept\"]},
           \"credentials\":[{\"type\":\"password\",\"value\":\"$password\",
           \"temporary\":false}]}" \
      -D - | grep -i location | awk -F'/' '{print $NF}' | tr -d '\r')
  fi

  if [ -z "$user_id" ]; then
    echo "Failed to create or find user: $username"
    exit 1
  fi

  curl -s -X PUT "$KC_URL/admin/realms/govportal/users/$user_id/reset-password" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"password\",\"value\":\"$password\",\"temporary\":false}" > /dev/null

  curl -s -X PUT "$KC_URL/admin/realms/govportal/users/$user_id" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"requiredActions":[],"emailVerified":true}' > /dev/null

  # Gán role
  role_id=$(curl -s "$KC_URL/admin/realms/govportal/roles/$role" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id", ""))')
  curl -s -X POST "$KC_URL/admin/realms/govportal/users/$user_id/role-mappings/realm" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "[{\"id\":\"$role_id\",\"name\":\"$role\"}]" > /dev/null
  echo "Ready: $username ($role/$dept)"
}
 
create_user citizen001 c001@test.vn Test@1234 CITIZEN A
create_user citizen002 c002@test.vn Test@1234 CITIZEN A
create_user officer001 o001@test.vn Officer@1234 OFFICER IT
create_user officer002 o002@test.vn Officer@1234 OFFICER HR
create_user auditor001 a001@test.vn Audit@1234 AUDITOR ALL
echo '✓ Seed data done!'
