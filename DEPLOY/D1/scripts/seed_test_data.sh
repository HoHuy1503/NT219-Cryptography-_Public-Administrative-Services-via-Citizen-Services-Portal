#!/bin/bash
# DEPLOY/D1/scripts/seed_test_data.sh
KC_URL="http://localhost:8080"
 
# Lấy admin token
ADMIN_TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password" \
  -d "username=admin&password=${KC_ADMIN_PASS}" | jq -r .access_token)
 
create_user() {
  local username=$1 email=$2 password=$3 role=$4 dept=$5
  USER_ID=$(curl -s -X POST "$KC_URL/admin/realms/govportal/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$username\",\"email\":\"$email\",
         \"enabled\":true,\"attributes\":{\"dept\":[\"$dept\"]},
         \"credentials\":[{\"type\":\"password\",\"value\":\"$password\",
         \"temporary\":false}]}" \
    -D - | grep -i location | awk -F'/' '{print $NF}' | tr -d '\r')
  # Gán role
  ROLE_ID=$(curl -s "$KC_URL/admin/realms/govportal/roles/$role" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .id)
  curl -s -X POST "$KC_URL/admin/realms/govportal/users/$USER_ID/role-mappings/realm" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "[{\"id\":\"$ROLE_ID\",\"name\":\"$role\"}]"
  echo "Created: $username ($role/$dept)"
}
 
create_user citizen001 c001@test.vn Test@1234 CITIZEN A
create_user citizen002 c002@test.vn Test@1234 CITIZEN A
create_user officer001 o001@test.vn Officer@1234 OFFICER IT
create_user officer002 o002@test.vn Officer@1234 OFFICER HR
create_user auditor001 a001@test.vn Audit@1234 AUDITOR ALL
echo '✓ Seed data done!'
