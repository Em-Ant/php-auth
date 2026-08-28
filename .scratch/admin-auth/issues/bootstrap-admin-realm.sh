#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://auth.example.com"
API_KEY="CHANGE_ME"
REALM_NAME="admin"
REALM_SCOPE="openid profile email offline_access"
ADMIN_UI_NAME="admin-ui"
ADMIN_UI_URI="https://admin-ui.example.com/*"
ADMIN_UI_SCOPE="openid profile email"
CI_NAME="ci-deployer"
CI_URI="https://ci.example.com"
CI_SCOPE="openid profile email offline_access"
ADMIN_EMAIL="admin@example.com"
ADMIN_USER_NAME="admin"
ACCESS_TOKEN_EXPIRES_IN=300
REFRESH_TOKEN_EXPIRES_IN=1800
SESSION_EXPIRES_IN=86400
IDLE_SESSION_EXPIRES_IN=1800
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
CI_SECRET="${CI_SECRET:-}"

AUTH="X-Admin-Key: $API_KEY"
H_JSON="Content-Type: application/json"

if [ -z "$ADMIN_PASSWORD" ]; then ADMIN_PASSWORD="$(openssl rand -base64 24)"; fi
if [ -z "$CI_SECRET" ]; then CI_SECRET="$(openssl rand -base64 32)"; fi

echo "==> Bootstrapping realm '$REALM_NAME' on $BASE_URL"
echo "    admin password: $ADMIN_PASSWORD"
echo "    ci-deployer secret: $CI_SECRET"
echo

REALM_ID="$(curl -sf -H "$AUTH" "$BASE_URL/admin/realms" | jq -r --arg name "$REALM_NAME" 'first(.realms[]? | select(.name==$name)) | .id?')"
if [ -z "$REALM_ID" ]; then
    KID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" "$BASE_URL/admin/keys" | jq -er '.kid')"
    echo "==> created keys: kid=$KID"
    REALM_ID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"name\":\"$REALM_NAME\",\"keys_id\":\"$KID\",\"scope\":\"$REALM_SCOPE\",\"access_token_expires_in\":$ACCESS_TOKEN_EXPIRES_IN,\"refresh_token_expires_in\":$REFRESH_TOKEN_EXPIRES_IN,\"session_expires_in\":$SESSION_EXPIRES_IN,\"idle_session_expires_in\":$IDLE_SESSION_EXPIRES_IN}" "$BASE_URL/admin/realms" | jq -er '.id')"
    echo "==> created realm: id=$REALM_ID"
else
    echo "==> realm '$REALM_NAME' already exists (id=$REALM_ID)"
fi

ROLE_ID="$(curl -sf -H "$AUTH" "$BASE_URL/admin/roles?realm_id=$REALM_ID" | jq -r --arg name "admin" 'first(.items[]? | select(.name==$name and .client_id==null)) | .id?')"
if [ -z "$ROLE_ID" ]; then
    ROLE_ID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"name\":\"admin\",\"realm_id\":\"$REALM_ID\",\"client_id\":null}" "$BASE_URL/admin/roles" | jq -er '.id')"
    echo "==> created role 'admin': id=$ROLE_ID"
else
    echo "==> role 'admin' already exists: id=$ROLE_ID"
fi

USER_ID="$(curl -sf -H "$AUTH" "$BASE_URL/admin/users?realm_id=$REALM_ID" | jq -r --arg email "$ADMIN_EMAIL" 'first(.items[]? | select(.email==$email)) | .id?')"
if [ -z "$USER_ID" ]; then
    USER_ID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"realm_id\":\"$REALM_ID\",\"email\":\"$ADMIN_EMAIL\",\"name\":\"$ADMIN_USER_NAME\",\"password\":\"$ADMIN_PASSWORD\"}" "$BASE_URL/admin/users" | jq -er '.id')"
    echo "==> created admin user: id=$USER_ID"
else
    echo "==> admin user already exists: id=$USER_ID"
fi

if curl -sf -H "$AUTH" "$BASE_URL/admin/users/$USER_ID/roles" | jq -e --arg id "$ROLE_ID" '.items[]? | select(.id==$id)' >/dev/null; then
    echo "==> admin role already assigned to user"
else
    curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"role_id\":\"$ROLE_ID\"}" "$BASE_URL/admin/users/$USER_ID/roles" >/dev/null
    echo "==> assigned role '$ROLE_ID' to user '$USER_ID'"
fi

ADMIN_UI_ID="$(curl -sf -H "$AUTH" "$BASE_URL/admin/clients?realm_id=$REALM_ID" | jq -r --arg name "$ADMIN_UI_NAME" --arg uri "$ADMIN_UI_URI" 'first(.items[]? | select(.name==$name and .uri==$uri)) | .id?')"
if [ -z "$ADMIN_UI_ID" ]; then
    ADMIN_UI_ID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"name\":\"$ADMIN_UI_NAME\",\"realm_id\":\"$REALM_ID\",\"uri\":\"$ADMIN_UI_URI\",\"require_auth\":false,\"scope\":\"$ADMIN_UI_SCOPE\"}" "$BASE_URL/admin/clients" | jq -er '.id')"
    echo "==> created client '$ADMIN_UI_NAME': id=$ADMIN_UI_ID"
else
    echo "==> client '$ADMIN_UI_NAME' already exists: id=$ADMIN_UI_ID"
fi

CI_ID="$(curl -sf -H "$AUTH" "$BASE_URL/admin/clients?realm_id=$REALM_ID" | jq -r --arg name "$CI_NAME" --arg uri "$CI_URI" 'first(.items[]? | select(.name==$name and .uri==$uri)) | .id?')"
if [ -z "$CI_ID" ]; then
    CI_ID="$(curl -sf -X POST -H "$AUTH" -H "$H_JSON" -d "{\"name\":\"$CI_NAME\",\"realm_id\":\"$REALM_ID\",\"uri\":\"$CI_URI\",\"require_auth\":true,\"client_secret\":\"$CI_SECRET\",\"scope\":\"$CI_SCOPE\"}" "$BASE_URL/admin/clients" | jq -er '.id')"
    echo "==> created client '$CI_NAME': id=$CI_ID"
else
    echo "==> client '$CI_NAME' already exists: id=$CI_ID"
fi

echo
echo "==> Done. Realm: $REALM_ID | role: $ROLE_ID | admin user: $USER_ID"
echo "==> admin-ui: $ADMIN_UI_ID | ci-deployer: $CI_ID"
echo "==> JWKS check: $BASE_URL/realms/$REALM_NAME/protocol/openid-connect/certs"