#!/usr/bin/env bash
set -euo pipefail

# E2E smoke test against production — simulates what Keycloak app does.
# Usage:  bash bin/e2e-test-keycloak.sh
# Env:    BASE_URL defaults to https://emant.altervista.org/id
#         REALM   defaults to test
#         CLIENT  defaults to kc_app

BASE_URL="${BASE_URL:-https://emant.altervista.org/id}"
REALM="${REALM:-test}"
CLIENT="${CLIENT:-kc_app}"
REDIRECT_URI="${REDIRECT_URI:-https://www.keycloak.org/app}"
COOKIE_JAR=$(mktemp)
HEADER_DUMP=$(mktemp)
PASS=0
FAIL=0

cleanup() {
    local exit_code=$?
    rm -f "$COOKIE_JAR" "$HEADER_DUMP"
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

echo "=== E2E: Keycloak app smoke test ==="
echo "Target: $BASE_URL | realm=$REALM | client=$CLIENT"
echo ""

# ── Step 1: OIDC discovery ─────────────────────────────────────
echo "=== Step 1: OIDC discovery ==="
CONFIG=$(curl -sf "$BASE_URL/realms/$REALM/.well-known/openid-configuration") || {
    fail "Discovery endpoint unreachable"
    exit 1
}
ok "Discovery reachable"

echo "$CONFIG" | grep -q '"issuer"'        && ok "issuer present"        || fail "issuer missing"
echo "$CONFIG" | grep -q '"authorization_endpoint"' && ok "authorization_endpoint present" || fail "authorization_endpoint missing"
echo "$CONFIG" | grep -q '"token_endpoint"' && ok "token_endpoint present"   || fail "token_endpoint missing"
echo "$CONFIG" | grep -q '"jwks_uri"'       && ok "jwks_uri present"         || fail "jwks_uri missing"
echo "$CONFIG" | grep -q '"userinfo_endpoint"' && ok "userinfo_endpoint present" || fail "userinfo_endpoint missing"

# ── Step 2: GET /auth (login page) ─────────────────────────────
echo ""
echo "=== Step 2: GET /auth ==="
AUTH_PAGE=$(curl -sS -c "$COOKIE_JAR" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/auth?client_id=$CLIENT&redirect_uri=$REDIRECT_URI&response_type=code&response_mode=query&scope=openid&state=e2e-state&nonce=e2e-nonce")

if echo "$AUTH_PAGE" | grep -qi 'login\|sign in'; then
    ok "Auth endpoint returned login form"
else
    fail "Auth endpoint did not return login form"
fi

LOGIN_ID=$(echo "$AUTH_PAGE" | sed -n 's/.*action="[^"]*?q=\([^"]*\)".*/\1/p')
CSRF_TOKEN=$(echo "$AUTH_PAGE" | sed -n 's/.*name="csrf_token"\s*value="\([^"]*\)".*/\1/p')

[ -n "$LOGIN_ID" ]   && ok "Extracted login_id: ${LOGIN_ID:0:8}..."   || { fail "login_id missing"; exit 1; }
[ -n "$CSRF_TOKEN" ] && ok "Extracted csrf_token: ${CSRF_TOKEN:0:8}..." || { fail "csrf_token missing"; exit 1; }

# ── Step 3: POST login (authenticate) ──────────────────────────
echo ""
echo "=== Step 3: POST login ==="
> "$HEADER_DUMP"
HTTP_CODE=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -D "$HEADER_DUMP" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=test@example.com&password=tst&csrf_token=${CSRF_TOKEN}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/login-actions/authenticate?q=${LOGIN_ID}")

if [ "$HTTP_CODE" != "302" ]; then
    fail "Login expected 302, got $HTTP_CODE"
    exit 1
fi
ok "Login returned 302 redirect"

LOCATION=$(grep -i '^location:' "$HEADER_DUMP" | sed 's/.*location: //I' | tr -d '\r\n')
AUTH_CODE=$(echo "$LOCATION" | sed 's/.*code=\([^&]*\).*/\1/')

if [ -n "$AUTH_CODE" ]; then
    ok "Auth code: ${AUTH_CODE:0:8}..."
else
    fail "No auth code in Location header"
    echo "  Location: $LOCATION"
    exit 1
fi

# ── Step 4: POST /token ────────────────────────────────────────
echo ""
echo "=== Step 4: POST /token ==="
TOKEN_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=$CLIENT&code=${AUTH_CODE}&redirect_uri=$REDIRECT_URI" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p')
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"token_type":"\([^"]*\)".*/\1/p')

[ -n "$ACCESS_TOKEN" ] && ok "Got access_token"  || { fail "No access_token"; exit 1; }
[ -n "$REFRESH_TOKEN" ] && ok "Got refresh_token" || fail "No refresh_token"
[ -n "$ID_TOKEN" ]      && ok "Got id_token"      || fail "No id_token"
[ "$TOKEN_TYPE" = "Bearer" ] && ok "token_type is Bearer" || fail "token_type: $TOKEN_TYPE"

# ── Step 5: GET /certs (JWKS) ──────────────────────────────────
echo ""
echo "=== Step 5: GET /certs ==="
CERTS=$(curl -sf "$BASE_URL/realms/$REALM/protocol/openid-connect/certs") || {
    fail "Certs endpoint unreachable"
    exit 1
}
echo "$CERTS" | grep -q '"keys"' && ok "/certs returns keys" || fail "/certs missing keys array"

# ── Step 6: GET /userinfo ──────────────────────────────────────
echo ""
echo "=== Step 6: GET /userinfo ==="
USERINFO=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/userinfo") || {
    fail "Userinfo endpoint unreachable"
    exit 1
}
echo "$USERINFO" | grep -q '"sub"' && ok "Userinfo returns sub" || fail "Userinfo missing sub"

# ── Step 7: Refresh token ──────────────────────────────────────
echo ""
echo "=== Step 7: Refresh token ==="
REFRESH_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=$CLIENT&refresh_token=${REFRESH_TOKEN}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")

NEW_ACCESS=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
NEW_REFRESH=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[ -n "$NEW_ACCESS" ] && ok "Refresh produced new access_token" || fail "No access_token after refresh"
[ -n "$NEW_REFRESH" ] && [ "$NEW_REFRESH" != "$REFRESH_TOKEN" ] \
    && ok "Refresh token rotated" \
    || fail "Refresh token not rotated"

exit $FAIL
