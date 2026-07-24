#!/usr/bin/env bash
set -euo pipefail

HOST=localhost
PORT=8000
BASE="http://${HOST}:${PORT}"
COOKIE_JAR=$(mktemp)
HEADER_DUMP=$(mktemp)
PASS=0
FAIL=0

cleanup() {
    local exit_code=$?
    rm -f "$COOKIE_JAR" "$HEADER_DUMP"
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

# ── Start dev server ──────────────────────────────────────────
echo "=== Starting dev server ==="

php -S "${HOST}:${PORT}" -t public router.php >/dev/null 2>&1 &
SERVER_PID=$!

for i in $(seq 1 20); do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then
        ok "Server up at $BASE"
        break
    fi
    if [ "$i" -eq 20 ]; then
        fail "Server failed to start"
        exit 1
    fi
    sleep 0.3
done

# ── Step 1: GET /auth ─────────────────────────────────────────
echo ""
echo "=== Step 1: GET /auth ==="
AUTH_PAGE=$(curl -sS -c "$COOKIE_JAR" \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/app&response_type=code&response_mode=query&scope=openid&state=e2e-state&nonce=e2e-nonce")

if echo "$AUTH_PAGE" | grep -q 'login'; then
    ok "Auth endpoint returned login form"
else
    fail "Auth endpoint did not return login form"
fi

LOGIN_ID=$(echo "$AUTH_PAGE" | sed -n 's/.*action="[^"]*?q=\([^"]*\)".*/\1/p')
CSRF_TOKEN=$(echo "$AUTH_PAGE" | sed -n 's/.*name="csrf_token"\s*value="\([^"]*\)".*/\1/p')

[ -n "$LOGIN_ID" ]   && ok "Extracted login_id: ${LOGIN_ID:0:8}..."   || { fail "login_id missing"; exit 1; }
[ -n "$CSRF_TOKEN" ] && ok "Extracted csrf_token: ${CSRF_TOKEN:0:8}..." || { fail "csrf_token missing"; exit 1; }

# ── Step 2: POST login ────────────────────────────────────────
echo ""
echo "=== Step 2: POST login ==="
> "$HEADER_DUMP"
HTTP_CODE=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -D "$HEADER_DUMP" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=test@example.com&password=tst&csrf_token=${CSRF_TOKEN}" \
    "$BASE/realms/test/protocol/openid-connect/login-actions/authenticate?q=${LOGIN_ID}")

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

# ── Step 3: POST /token ───────────────────────────────────────
echo ""
echo "=== Step 3: POST /token ==="
TOKEN_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=kc_app&code=${AUTH_CODE}&redirect_uri=https://www.keycloak.org/app" \
    "$BASE/realms/test/protocol/openid-connect/token")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p')
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"token_type":"\([^"]*\)".*/\1/p')

[ -n "$ACCESS_TOKEN" ] && ok "Got access_token"  || { fail "No access_token"; exit 1; }
[ -n "$REFRESH_TOKEN" ] && ok "Got refresh_token" || fail "No refresh_token"
[ -n "$ID_TOKEN" ]      && ok "Got id_token"      || fail "No id_token"
[ "$TOKEN_TYPE" = "Bearer" ] && ok "token_type is Bearer" || fail "token_type: $TOKEN_TYPE"

# ── Step 4: Introspect active tokens ─────────────────────────
echo ""
echo "=== Step 4: Introspect active tokens ==="

INTRO_ACCESS=$(curl -sS -X POST \
    -d "token=${ACCESS_TOKEN}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_ACCESS" | grep -q '"active":true' && ok "Access token is active" || { fail "Access token not active"; exit 1; }
echo "$INTRO_ACCESS" | grep -q '"token_type":"Bearer"' && ok "token_type is Bearer" || fail "token_type not Bearer"

INTRO_REFRESH=$(curl -sS -X POST \
    -d "token=${REFRESH_TOKEN}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_REFRESH" | grep -q '"active":true' && ok "Refresh token is active" || fail "Refresh token not active"
echo "$INTRO_REFRESH" | grep -q '"token_type":"refresh_token"' && ok "token_type is refresh_token" || fail "token_type not refresh_token"

INTRO_ID=$(curl -sS -X POST \
    -d "token=${ID_TOKEN}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_ID" | grep -q '"active":true' && ok "ID token is active" || fail "ID token not active"
echo "$INTRO_ID" | grep -q '"token_type":"ID"' && ok "token_type is ID" || fail "token_type not ID"

# ── Step 5: Introspect with bad client creds ────────────────────
echo ""
echo "=== Step 5: Introspect with bad client credentials ==="
BAD_AUTH_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "token=${ACCESS_TOKEN}&client_id=nonexistent" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

[ "$BAD_AUTH_CODE" = "401" ] && ok "Bad client returns 401" || fail "Bad client expected 401, got $BAD_AUTH_CODE"

# ── Step 6: Introspect garbage token ──────────────────────────
echo ""
echo "=== Step 6: Introspect garbage token ==="
INTRO_GARBAGE=$(curl -sS -X POST \
    -d "token=not-a-jwt&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_GARBAGE" | grep -q '"active":false' && ok "Garbage token is not active" || fail "Garbage token should not be active"

# ── Step 7: Refresh token ─────────────────────────────────────
echo ""
echo "=== Step 7: Refresh token ==="
REFRESH_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=kc_app&refresh_token=${REFRESH_TOKEN}" \
    "$BASE/realms/test/protocol/openid-connect/token")

NEW_ACCESS=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
NEW_REFRESH=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[ -n "$NEW_ACCESS" ] && ok "Refresh produced new access_token" || fail "No access_token after refresh"
[ -n "$NEW_REFRESH" ] && [ "$NEW_REFRESH" != "$REFRESH_TOKEN" ] \
    && ok "Refresh token rotated" \
    || fail "Refresh token not rotated"

# ── Step 8: Revoke refresh token ──────────────────────────────
echo ""
echo "=== Step 8: Revoke refresh token ==="
# Use the current (post-rotation) refresh token
REVOKE_RESPONSE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "kc_app:" \
    -d "token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/revoke")

[ "$REVOKE_RESPONSE" = "200" ] && ok "Revoke returned 200" || { fail "Revoke expected 200, got $REVOKE_RESPONSE"; exit 1; }

# Try to use the revoked refresh token
USED_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=kc_app&refresh_token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/token" | grep -cE 'expired|invalid' || true)

[ "$USED_REFRESH" -gt 0 ] && ok "Revoked refresh token rejected" || fail "Revoked refresh token was accepted"

# ── Step 9: Revoke access token ───────────────────────────────
echo ""
echo "=== Step 9: Revoke access token ==="
REVOKE_AT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "kc_app:" \
    -d "token_type_hint=access_token&token=${NEW_ACCESS}" \
    "$BASE/realms/test/protocol/openid-connect/revoke")

[ "$REVOKE_AT" = "200" ] && ok "Revoke access token returned 200" || { fail "Revoke access token expected 200, got $REVOKE_AT"; exit 1; }

# Verify revoked access token is rejected at userinfo
USERINFO_CHECK=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${NEW_ACCESS}" \
    "$BASE/realms/test/protocol/openid-connect/userinfo")

[ "$USERINFO_CHECK" = "401" ] && ok "Revoked access token rejected at userinfo" || fail "Revoked access token was accepted at userinfo (got $USERINFO_CHECK)"

# ── Step 10: Introspect revoked access token ────────────────────
echo ""
echo "=== Step 10: Introspect revoked access token ==="
INTRO_REVOKED=$(curl -sS -X POST \
    -d "token=${NEW_ACCESS}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_REVOKED" | grep -q '"active":false' && ok "Revoked access token shows inactive" || fail "Revoked access token should be inactive"

# ── All done ──────────────────────────────────────────────────
exit $FAIL
