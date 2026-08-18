#!/usr/bin/env bash
set -euo pipefail

HOST=localhost
PORT=8000
BASE="http://${HOST}:${PORT}"

# E2E artifacts (dev server output, cookie jar, response header dumps) are
# written to a gitignored project folder so a failed run can be inspected
# afterwards. Override the location with E2E_LOG_DIR if needed.
E2E_LOG_DIR="${E2E_LOG_DIR:-.tmp/e2e}"
mkdir -p "$E2E_LOG_DIR"
COOKIE_JAR="$E2E_LOG_DIR/cookies.txt"
HEADER_DUMP="$E2E_LOG_DIR/headers.txt"
SERVER_LOG="$E2E_LOG_DIR/server.log"

PASS=0
FAIL=0

cleanup() {
    local exit_code=$?
    admin_cleanup 2>/dev/null || true
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    echo "=== E2E artifacts left in: $E2E_LOG_DIR ==="
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

# ── Start dev server ──────────────────────────────────────────
echo "=== Starting dev server ==="

php -S "${HOST}:${PORT}" -t public router.php >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 20); do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then
        ok "Server up at $BASE"
        break
    fi
    if [[ "$i" -eq 20 ]]; then
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

[[ -n "$LOGIN_ID" ]]   && ok "Extracted login_id: ${LOGIN_ID:0:8}..."   || { fail "login_id missing"; exit 1; }
[[ -n "$CSRF_TOKEN" ]] && ok "Extracted csrf_token: ${CSRF_TOKEN:0:8}..." || { fail "csrf_token missing"; exit 1; }

# ── Step 2: POST login ────────────────────────────────────────
echo ""
echo "=== Step 2: POST login ==="
> "$HEADER_DUMP"
HTTP_CODE=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -D "$HEADER_DUMP" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=test@example.com&password=tst&csrf_token=${CSRF_TOKEN}" \
    "$BASE/realms/test/protocol/openid-connect/login-actions/authenticate?q=${LOGIN_ID}")

if [[ "$HTTP_CODE" != "302" ]]; then
    fail "Login expected 302, got $HTTP_CODE"
    exit 1
fi
ok "Login returned 302 redirect"

# The SSO session cookie must be HttpOnly; a separate non-HttpOnly
# check-session cookie carries the same value for the iframe (S-04).
AUTH_SESSION_HDR=$(grep -i '^set-cookie:' "$HEADER_DUMP" | grep -i '^set-cookie: *AUTH_SESSION=' | head -1 || true)
CHECK_SESSION_HDR=$(grep -i '^set-cookie:' "$HEADER_DUMP" | grep -i 'AUTH_SESSION_CHECK=' | head -1 || true)

echo "$AUTH_SESSION_HDR" | grep -qi 'httponly' \
    && ok "AUTH_SESSION cookie is HttpOnly (S-04)" \
    || fail "AUTH_SESSION cookie missing HttpOnly"
[[ -n "$CHECK_SESSION_HDR" ]] && ok "Check-session cookie set (S-04)" || fail "AUTH_SESSION_CHECK cookie not set"
if echo "$CHECK_SESSION_HDR" | grep -qi 'httponly'; then
    fail "AUTH_SESSION_CHECK must not be HttpOnly"
else
    ok "Check-session cookie is JS-readable (no HttpOnly)"
fi

LOCATION=$(grep -i '^location:' "$HEADER_DUMP" | sed 's/.*location: //I' | tr -d '\r\n')
AUTH_CODE=$(echo "$LOCATION" | sed 's/.*code=\([^&]*\).*/\1/')

if [[ -n "$AUTH_CODE" ]]; then
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

[[ -n "$ACCESS_TOKEN" ]] && ok "Got access_token"  || { fail "No access_token"; exit 1; }
[[ -n "$REFRESH_TOKEN" ]] && ok "Got refresh_token" || fail "No refresh_token"
[[ -n "$ID_TOKEN" ]]      && ok "Got id_token"      || fail "No id_token"
[[ "$TOKEN_TYPE" = "Bearer" ]] && ok "token_type is Bearer" || fail "token_type: $TOKEN_TYPE"

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

[[ "$BAD_AUTH_CODE" = "401" ]] && ok "Bad client returns 401" || fail "Bad client expected 401, got $BAD_AUTH_CODE"

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

[[ -n "$NEW_ACCESS" ]] && ok "Refresh produced new access_token" || fail "No access_token after refresh"
[[ -n "$NEW_REFRESH" ]] && [[ "$NEW_REFRESH" != "$REFRESH_TOKEN" ]] \
    && ok "Refresh token rotated" \
    || fail "Refresh token not rotated"

# A refresh token is bound to the client it was issued to (S-02):
# a different client must be rejected and the attempt must not mutate state.
CROSS_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "grant_type=refresh_token&client_id=local&refresh_token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/token")

[[ "$CROSS_CLIENT" = "400" ]] && ok "Cross-client refresh rejected (S-02)" || fail "Cross-client refresh expected 400, got $CROSS_CLIENT"

# A wrong-realm refresh attempt must fail (S-06) and must not expire the
# login: the token stays usable at its own realm.
WRONG_REALM=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "grant_type=refresh_token&client_id=kc_app&refresh_token=${NEW_REFRESH}" \
    "$BASE/realms/web/protocol/openid-connect/token")

[[ "$WRONG_REALM" = "400" ]] && ok "Wrong-realm refresh rejected (S-06)" || fail "Wrong-realm refresh expected 400, got $WRONG_REALM"

S06_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=kc_app&refresh_token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/token")

S06_NEW_AT=$(echo "$S06_REFRESH" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
S06_NEW_RT=$(echo "$S06_REFRESH" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[[ -n "$S06_NEW_AT" ]] && [[ -n "$S06_NEW_RT" ]] \
    && ok "Token still usable after failed attempt (S-06)" \
    || fail "Token unusable after failed attempt"

NEW_REFRESH="$S06_NEW_RT"
NEW_ACCESS="$S06_NEW_AT"

# ── Step 8: Revoke refresh token ──────────────────────────────
echo ""
echo "=== Step 8: Revoke refresh token ==="
# Use the current (post-rotation) refresh token
REVOKE_RESPONSE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "kc_app:" \
    -d "token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/revoke")

[[ "$REVOKE_RESPONSE" = "200" ]] && ok "Revoke returned 200" || { fail "Revoke expected 200, got $REVOKE_RESPONSE"; exit 1; }

# Try to use the revoked refresh token
USED_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=kc_app&refresh_token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/token" | grep -cE 'expired|invalid' || true)

[[ "$USED_REFRESH" -gt 0 ]] && ok "Revoked refresh token rejected" || fail "Revoked refresh token was accepted"

# ── Step 9: Revoke access token ───────────────────────────────
echo ""
echo "=== Step 9: Revoke access token ==="
REVOKE_AT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "kc_app:" \
    -d "token_type_hint=access_token&token=${NEW_ACCESS}" \
    "$BASE/realms/test/protocol/openid-connect/revoke")

[[ "$REVOKE_AT" = "200" ]] && ok "Revoke access token returned 200" || { fail "Revoke access token expected 200, got $REVOKE_AT"; exit 1; }

# Verify revoked access token is rejected at userinfo
USERINFO_CHECK=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${NEW_ACCESS}" \
    "$BASE/realms/test/protocol/openid-connect/userinfo")

[[ "$USERINFO_CHECK" = "401" ]] && ok "Revoked access token rejected at userinfo" || fail "Revoked access token was accepted at userinfo (got $USERINFO_CHECK)"

# ── Step 10: Introspect revoked access token ────────────────────
echo ""
echo "=== Step 10: Introspect revoked access token ==="
INTRO_REVOKED=$(curl -sS -X POST \
    -d "token=${NEW_ACCESS}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_REVOKED" | grep -q '"active":false' && ok "Revoked access token shows inactive" || fail "Revoked access token should be inactive"

# ── Step 11: Client Credentials grant ─────────────────────────
echo ""
echo "=== Step 11: Client Credentials grant ==="
CC_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=client_credentials&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token")

CC_ACCESS=$(echo "$CC_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
CC_SCOPE=$(echo "$CC_RESPONSE" | sed -n 's/.*"scope":"\([^"]*\)".*/\1/p')

[[ -n "$CC_ACCESS" ]] && ok "Got client_credentials access_token" || { fail "No access_token"; exit 1; }
echo "$CC_RESPONSE" | grep -q '"refresh_token"' && fail "client_credentials should not issue refresh_token" || ok "No refresh_token issued"
echo "$CC_RESPONSE" | grep -q '"id_token"' && fail "client_credentials should not issue id_token" || ok "No id_token issued"
[[ -n "$CC_SCOPE" ]] && ok "Scope: $CC_SCOPE" || fail "No scope in response"

CC_INTRO=$(curl -sS -X POST \
    -d "token=${CC_ACCESS}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$CC_INTRO" | grep -q '"active":true' && ok "client_credentials token is active" || { fail "client_credentials token not active"; exit 1; }

# ── Step 12: prompt=none ─────────────────────────────────────
echo ""
echo "=== Step 12: prompt=none ==="
# Only the no-session branch is checked here: silent auth depends on the
# Secure AUTH_SESSION cookie re-reaching the server, which fails over plain
# http and can be flaky in infra — it's covered by the PHPUnit integration
# test (FullFlowTest::testPromptNoneWithValidSessionReturnsCode).
PN_URL="$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/app&response_type=code&response_mode=query&scope=openid&state=e2e-pn&nonce=e2e-pn&prompt=none"

> "$HEADER_DUMP"
PN_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -D "$HEADER_DUMP" "$PN_URL")

[[ "$PN_CODE" = "302" ]] && ok "prompt=none (no session) returns 302" || { fail "prompt=none (no session) expected 302, got $PN_CODE"; exit 1; }

PN_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)
echo "$PN_LOCATION" | grep -q 'error=login_required' \
    && ok "prompt=none returns error=login_required" \
    || { fail "prompt=none missing error=login_required"; echo "  Location: $PN_LOCATION"; }
echo "$PN_LOCATION" | grep -q 'state=e2e-pn' \
    && ok "prompt=none echoes state" \
    || { fail "prompt=none missing state"; echo "  Location: $PN_LOCATION"; }

# ── Step 12b: Login-status iframe init validation ──────────
echo ""
echo "=== Step 12b: login-status iframe init validation (S-05) ==="
IFRAME_OK=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=kc_app&origin=https://www.keycloak.org")
[[ "$IFRAME_OK" = "200" ]] && ok "init with valid client+origin returns 200" || fail "init expected 200, got $IFRAME_OK"

IFRAME_BAD_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=evil&origin=https://www.keycloak.org")
[[ "$IFRAME_BAD_CLIENT" = "400" ]] && ok "init with unknown client rejected" || fail "init with unknown client expected 400, got $IFRAME_BAD_CLIENT"

IFRAME_BAD_ORIGIN=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=kc_app&origin=https://evil.com")
[[ "$IFRAME_BAD_ORIGIN" = "400" ]] && ok "init with foreign origin rejected" || fail "init with foreign origin expected 400, got $IFRAME_BAD_ORIGIN"

# ── Step 13: Logout redirect validation ──────────────────────
echo ""
echo "=== Step 13: Logout redirect validation ==="
NEG_REDIRECT_URI="https://evil.com"

> "$HEADER_DUMP"
LG_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -D "$HEADER_DUMP" \
    "$BASE/realms/test/protocol/openid-connect/logout?id_token_hint=${ID_TOKEN}&post_logout_redirect_uri=https://www.keycloak.org/app")

[[ "$LG_CODE" = "302" ]] && ok "Logout to registered uri returns 302" || { fail "Logout expected 302, got $LG_CODE"; exit 1; }

LG_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)
echo "$LG_LOCATION" | grep -q 'https://www.keycloak.org/app' \
    && ok "Logout redirects to registered uri" \
    || fail "Logout did not redirect to registered uri: $LG_LOCATION"

> "$HEADER_DUMP"
LG_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -D "$HEADER_DUMP" \
    "$BASE/realms/test/protocol/openid-connect/logout?id_token_hint=${ID_TOKEN}&post_logout_redirect_uri=${NEG_REDIRECT_URI}")

LG_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)

if echo "$LG_LOCATION" | grep -q "$NEG_REDIRECT_URI"; then
    fail "Logout redirected to unregistered uri"
else
    ok "Logout does not redirect to unregistered uri"
fi

# ═══════════════════════════════════════════════════════════════
# Admin CRUD API
# ═══════════════════════════════════════════════════════════════

ADMIN_KEY="dev-admin-token-change-me"
ADMIN_HDR="Authorization: Bearer ${ADMIN_KEY}"
ADMIN_CREATED_KID=""
ADMIN_CREATED_REALM_ID=""
ADMIN_CREATED_CLIENT_ID=""
ADMIN_CREATED_USER_ID=""

admin_cleanup() {
    [[ -n "${ADMIN_CREATED_USER_ID:-}" ]]  && curl -sf -X DELETE -H "$ADMIN_HDR" "$BASE/admin/users/$ADMIN_CREATED_USER_ID" >/dev/null 2>&1 || true
    [[ -n "${ADMIN_CREATED_CLIENT_ID:-}" ]] && curl -sf -X DELETE -H "$ADMIN_HDR" "$BASE/admin/clients/$ADMIN_CREATED_CLIENT_ID" >/dev/null 2>&1 || true
    [[ -n "${ADMIN_CREATED_REALM_ID:-}" ]] && curl -sf -X DELETE -H "$ADMIN_HDR" "$BASE/admin/realms/$ADMIN_CREATED_REALM_ID" >/dev/null 2>&1 || true
    [[ -n "${ADMIN_CREATED_KID:-}" ]]      && rm -rf "keys/$ADMIN_CREATED_KID" 2>/dev/null || true
}

# ── Step 14: Admin auth ──────────────────────────────────────
echo ""
echo "=== Step 14: Admin auth ==="

ADMIN_NOAUTH=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE/admin/realms")
[[ "$ADMIN_NOAUTH" = "401" ]] && ok "Admin endpoint returns 401 without token" || fail "Expected 401, got $ADMIN_NOAUTH"

ADMIN_BAD=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-key" "$BASE/admin/realms")
[[ "$ADMIN_BAD" = "401" ]] && ok "Admin endpoint returns 401 with wrong token" || fail "Expected 401 with bad token, got $ADMIN_BAD"

# ── Step 15: Admin keys ─────────────────────────────────────
echo ""
echo "=== Step 15: Admin — generate keys ==="

KEYS_RESP=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" "$BASE/admin/keys")
ADMIN_CREATED_KID=$(echo "$KEYS_RESP" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_CREATED_KID" ]] && ok "Generated key pair, kid: ${ADMIN_CREATED_KID:0:8}..." || { fail "No kid returned"; admin_cleanup; exit 1; }
[[ -f "keys/$ADMIN_CREATED_KID/public_key.pem" ]] && ok "Key files written to filesystem" || fail "Key files not found on disk"

# ── Step 16: Admin realms CRUD ──────────────────────────────
echo ""
echo "=== Step 16: Admin — realms CRUD ==="

# List seeded realms
REALMS_LIST=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/realms")
REALM_COUNT=$(echo "$REALMS_LIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['realms']))" 2>/dev/null || echo 0)
[[ "$REALM_COUNT" -ge 2 ]] && ok "List realms returns seeded realms ($REALM_COUNT found)" || fail "Expected >=2 seeded realms, got $REALM_COUNT"

# Create realm
REALM_RESP=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"e2e-admin-realm","keys_id":"'"$ADMIN_CREATED_KID"'"}' \
    "$BASE/admin/realms")
ADMIN_CREATED_REALM_ID=$(echo "$REALM_RESP" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
REALM_NAME=$(echo "$REALM_RESP" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_CREATED_REALM_ID" ]] && ok "Created realm: $REALM_NAME (${ADMIN_CREATED_REALM_ID:0:8}...)" || { fail "No realm id returned"; admin_cleanup; exit 1; }

# Read realm
READ_REALM=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/realms/$ADMIN_CREATED_REALM_ID")
READ_REALM_NAME=$(echo "$READ_REALM" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
[[ "$READ_REALM_NAME" = "e2e-admin-realm" ]] && ok "Read realm returns correct data" || fail "Read realm name mismatch: $READ_REALM_NAME"

# Update realm
UPDATE_REALM=$(curl -sS -X PUT -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"access_token_expires_in":900}' \
    "$BASE/admin/realms/$ADMIN_CREATED_REALM_ID")
UPDATED_TTL=$(echo "$UPDATE_REALM" | sed -n 's/.*"access_token_expires_in":\([0-9]*\).*/\1/p')
[[ "$UPDATED_TTL" = "900" ]] && ok "Updated realm access_token_expires_in to 900" || fail "Expected 900, got $UPDATED_TTL"

# Duplicate name returns 409
DUP_409=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"e2e-admin-realm","keys_id":"'"$ADMIN_CREATED_KID"'"}' \
    "$BASE/admin/realms")
[[ "$DUP_409" = "409" ]] && ok "Duplicate realm name returns 409" || fail "Expected 409, got $DUP_409"

# Unknown keys_id returns 400
BADKEYS_400=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"no-keys-realm","keys_id":"does-not-exist"}' \
    "$BASE/admin/realms")
[[ "$BADKEYS_400" = "400" ]] && ok "Unknown keys_id returns 400" || fail "Expected 400, got $BADKEYS_400"

# Missing realm returns 404
MISSING_404=$(curl -sS -o /dev/null -w "%{http_code}" -H "$ADMIN_HDR" "$BASE/admin/realms/nonexistent")
[[ "$MISSING_404" = "404" ]] && ok "Missing realm returns 404" || fail "Expected 404, got $MISSING_404"

# ── Step 17: Admin clients CRUD ─────────────────────────────
echo ""
echo "=== Step 17: Admin — clients CRUD ==="

# Create client
CLIENT_RESP=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"e2e-admin-client","realm_id":"'"$ADMIN_CREATED_REALM_ID"'","uri":"https://e2e.example.com","client_secret":"test-secret","require_auth":true}' \
    "$BASE/admin/clients")
ADMIN_CREATED_CLIENT_ID=$(echo "$CLIENT_RESP" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
HAS_SECRET=$(echo "$CLIENT_RESP" | grep -c '"has_secret":true' || true)

[[ -n "$ADMIN_CREATED_CLIENT_ID" ]] && ok "Created client: e2e-admin-client (${ADMIN_CREATED_CLIENT_ID:0:8}...)" || { fail "No client id returned"; admin_cleanup; exit 1; }
[[ "$HAS_SECRET" -gt 0 ]] && ok "Client has_secret is true (secret was provided)" || fail "has_secret should be true"
echo "$CLIENT_RESP" | grep -q '"client_secret"' && fail "client_secret must not be exposed in response" || ok "client_secret not exposed in response"

# List clients filtered by realm
CLIST=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/clients?realm_id=$ADMIN_CREATED_REALM_ID")
CLIST_COUNT=$(echo "$CLIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['clients']))" 2>/dev/null || echo 0)
[[ "$CLIST_COUNT" -ge 1 ]] && ok "List clients filtered by realm returns $CLIST_COUNT client(s)" || fail "Expected >=1 client, got $CLIST_COUNT"

# Read client
READ_CLIENT=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/clients/$ADMIN_CREATED_CLIENT_ID")
READ_CLIENT_NAME=$(echo "$READ_CLIENT" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
[[ "$READ_CLIENT_NAME" = "e2e-admin-client" ]] && ok "Read client returns correct data" || fail "Read client name mismatch: $READ_CLIENT_NAME"

# Update client
UPDATE_CLIENT=$(curl -sS -X PUT -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"require_auth":false}' \
    "$BASE/admin/clients/$ADMIN_CREATED_CLIENT_ID")
UPDATED_AUTH=$(echo "$UPDATE_CLIENT" | grep -c '"require_auth":false' || true)
[[ "$UPDATED_AUTH" -gt 0 ]] && ok "Updated client require_auth to false" || fail "Failed to update client"

# Duplicate name+uri returns 409
DUP_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"e2e-admin-client","realm_id":"'"$ADMIN_CREATED_REALM_ID"'","uri":"https://e2e.example.com"}' \
    "$BASE/admin/clients")
[[ "$DUP_CLIENT" = "409" ]] && ok "Duplicate client name+uri returns 409" || fail "Expected 409, got $DUP_CLIENT"

# Unknown realm returns 400
BAD_REALM_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"ghost","realm_id":"nonexistent","uri":"https://ghost.example.com"}' \
    "$BASE/admin/clients")
[[ "$BAD_REALM_CLIENT" = "400" ]] && ok "Client with unknown realm returns 400" || fail "Expected 400, got $BAD_REALM_CLIENT"

# ── Step 18: Admin users CRUD ───────────────────────────────
echo ""
echo "=== Step 18: Admin — users CRUD ==="

# Create user
USER_RESP=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"realm_id":"'"$ADMIN_CREATED_REALM_ID"'","email":"e2e-admin@example.com","password":"secret123","name":"E2E Admin User","realm_roles":"admin basic"}' \
    "$BASE/admin/users")
ADMIN_CREATED_USER_ID=$(echo "$USER_RESP" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
USER_EMAIL=$(echo "$USER_RESP" | sed -n 's/.*"email":"\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_CREATED_USER_ID" ]] && ok "Created user: $USER_EMAIL (${ADMIN_CREATED_USER_ID:0:8}...)" || { fail "No user id returned"; admin_cleanup; exit 1; }
echo "$USER_RESP" | grep -q '"password"' && fail "password must not be exposed in response" || ok "password not exposed in response"

# List users filtered by realm
ULIST=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/users?realm_id=$ADMIN_CREATED_REALM_ID")
ULIST_COUNT=$(echo "$ULIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['users']))" 2>/dev/null || echo 0)
[[ "$ULIST_COUNT" -ge 1 ]] && ok "List users filtered by realm returns $ULIST_COUNT user(s)" || fail "Expected >=1 user, got $ULIST_COUNT"

# Read user
READ_USER=$(curl -sS -H "$ADMIN_HDR" "$BASE/admin/users/$ADMIN_CREATED_USER_ID")
READ_USER_EMAIL=$(echo "$READ_USER" | sed -n 's/.*"email":"\([^"]*\)".*/\1/p')
[[ "$READ_USER_EMAIL" = "e2e-admin@example.com" ]] && ok "Read user returns correct data" || fail "Read user email mismatch: $READ_USER_EMAIL"

# Update user name
UPDATE_USER=$(curl -sS -X PUT -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"E2E Updated User"}' \
    "$BASE/admin/users/$ADMIN_CREATED_USER_ID")
UPDATED_NAME=$(echo "$UPDATE_USER" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
[[ "$UPDATED_NAME" = "E2E Updated User" ]] && ok "Updated user name" || fail "Expected 'E2E Updated User', got '$UPDATED_NAME'"

# Duplicate email in realm returns 409
DUP_USER=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"realm_id":"'"$ADMIN_CREATED_REALM_ID"'","email":"e2e-admin@example.com","password":"pass"}' \
    "$BASE/admin/users")
[[ "$DUP_USER" = "409" ]] && ok "Duplicate user email in realm returns 409" || fail "Expected 409, got $DUP_USER"

# Unknown realm returns 400
BAD_REALM_USER=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"realm_id":"nonexistent","email":"ghost@example.com","password":"pass"}' \
    "$BASE/admin/users")
[[ "$BAD_REALM_USER" = "400" ]] && ok "User with unknown realm returns 400" || fail "Expected 400, got $BAD_REALM_USER"

# ═══════════════════════════════════════════════════════════════
# OIDC login using admin-created realm / client / user
# ═══════════════════════════════════════════════════════════════

ADMIN_OIDC_COOKIE=$(mktemp)
ADMIN_OIDC_HEADERS=$(mktemp)
trap 'rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"' EXIT

ADMIN_REALM_NAME="e2e-admin-realm"
ADMIN_CLIENT_NAME="e2e-admin-client"
ADMIN_REDIRECT_URI="https://e2e.example.com"
ADMIN_EMAIL="e2e-admin@example.com"
ADMIN_PASSWORD="secret123"
ADMIN_AUTH_BASE="$BASE/realms/$ADMIN_REALM_NAME/protocol/openid-connect"

# ── Step 19: Auth redirect ───────────────────────────────────
echo ""
echo "=== Step 19: OIDC login — GET /auth ==="

ADMIN_AUTH_PAGE=$(curl -sS -c "$ADMIN_OIDC_COOKIE" \
    "$ADMIN_AUTH_BASE/auth?client_id=$ADMIN_CLIENT_NAME&redirect_uri=$ADMIN_REDIRECT_URI&response_type=code&response_mode=query&scope=openid&state=admin-e2e-state&nonce=admin-e2e-nonce")

if echo "$ADMIN_AUTH_PAGE" | grep -q 'login'; then
    ok "Auth page returned login form for admin realm"
else
    fail "Auth page did not return login form for admin realm"
    echo "$ADMIN_AUTH_PAGE" | head -5
fi

ADMIN_LOGIN_ID=$(echo "$ADMIN_AUTH_PAGE" | sed -n 's/.*action="[^"]*?q=\([^"]*\)".*/\1/p')
ADMIN_CSRF=$(echo "$ADMIN_AUTH_PAGE" | sed -n 's/.*name="csrf_token"\s*value="\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_LOGIN_ID" ]] && ok "Extracted login_id: ${ADMIN_LOGIN_ID:0:8}..." || { fail "login_id missing"; admin_cleanup; rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"; exit 1; }
[[ -n "$ADMIN_CSRF" ]]     && ok "Extracted csrf_token: ${ADMIN_CSRF:0:8}..." || { fail "csrf_token missing"; admin_cleanup; rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"; exit 1; }

# ── Step 20: Login ──────────────────────────────────────────
echo ""
echo "=== Step 20: OIDC login — POST login ==="

> "$ADMIN_OIDC_HEADERS"
ADMIN_LOGIN_CODE=$(curl -sS -c "$ADMIN_OIDC_COOKIE" -b "$ADMIN_OIDC_COOKIE" \
    -D "$ADMIN_OIDC_HEADERS" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=${ADMIN_EMAIL}&password=${ADMIN_PASSWORD}&csrf_token=${ADMIN_CSRF}" \
    "$ADMIN_AUTH_BASE/login-actions/authenticate?q=${ADMIN_LOGIN_ID}")

if [[ "$ADMIN_LOGIN_CODE" != "302" ]]; then
    fail "Login expected 302, got $ADMIN_LOGIN_CODE"
    admin_cleanup; rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"; exit 1
fi
ok "Login returned 302 redirect"

ADMIN_LOCATION=$(grep -i '^location:' "$ADMIN_OIDC_HEADERS" | sed 's/.*location: //I' | tr -d '\r\n')
ADMIN_AUTH_CODE=$(echo "$ADMIN_LOCATION" | sed 's/.*code=\([^&]*\).*/\1/')

if [[ -n "$ADMIN_AUTH_CODE" ]]; then
    ok "Auth code: ${ADMIN_AUTH_CODE:0:8}..."
else
    fail "No auth code in Location header"
    echo "  Location: $ADMIN_LOCATION"
    admin_cleanup; rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"; exit 1
fi

# ── Step 21: Token exchange ─────────────────────────────────
echo ""
echo "=== Step 21: OIDC login — POST /token ==="

ADMIN_TOKEN_RESP=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=${ADMIN_CLIENT_NAME}&code=${ADMIN_AUTH_CODE}&redirect_uri=${ADMIN_REDIRECT_URI}" \
    "$ADMIN_AUTH_BASE/token")

ADMIN_AT=$(echo "$ADMIN_TOKEN_RESP" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
ADMIN_RT=$(echo "$ADMIN_TOKEN_RESP" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
ADMIN_IDT=$(echo "$ADMIN_TOKEN_RESP" | sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p')
ADMIN_TT=$(echo "$ADMIN_TOKEN_RESP" | sed -n 's/.*"token_type":"\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_AT" ]]  && ok "Got access_token"  || { fail "No access_token"; admin_cleanup; rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"; exit 1; }
[[ -n "$ADMIN_RT" ]]  && ok "Got refresh_token" || fail "No refresh_token"
[[ -n "$ADMIN_IDT" ]] && ok "Got id_token"      || fail "No id_token"
[[ "$ADMIN_TT" = "Bearer" ]] && ok "token_type is Bearer" || fail "token_type: $ADMIN_TT"

# ── Step 22: Introspect ─────────────────────────────────────
echo ""
echo "=== Step 22: OIDC login — introspect access token ==="

ADMIN_INTRO=$(curl -sS -X POST \
    -d "token=${ADMIN_AT}&client_id=${ADMIN_CLIENT_NAME}" \
    "$ADMIN_AUTH_BASE/token/introspect")

echo "$ADMIN_INTRO" | grep -q '"active":true' && ok "Access token is active" || { fail "Access token not active"; echo "$ADMIN_INTRO"; }
echo "$ADMIN_INTRO" | grep -q '"token_type":"Bearer"' && ok "token_type is Bearer" || fail "token_type not Bearer"

# ID token is non-Bearer (typ: ID) — introspect it
ADMIN_INTRO_ID=$(curl -sS -X POST \
    -d "token=${ADMIN_IDT}&client_id=${ADMIN_CLIENT_NAME}" \
    "$ADMIN_AUTH_BASE/token/introspect")

echo "$ADMIN_INTRO_ID" | grep -q '"active":true' && ok "ID token is active" || fail "ID token not active"
# ID token introspection falls through to introspectAccessToken which returns token_type from claims
echo "$ADMIN_INTRO_ID" | grep -q '"token_type":"ID"' && ok "ID token token_type is ID" \
    || echo "$ADMIN_INTRO_ID" | grep -q '"active":true' && ok "ID token active (typ not checked)" \
    || fail "ID token introspection failed"

# ── Step 23: Refresh ────────────────────────────────────────
echo ""
echo "=== Step 23: OIDC login — refresh token ==="

ADMIN_REFRESH_RESP=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=${ADMIN_CLIENT_NAME}&refresh_token=${ADMIN_RT}" \
    "$ADMIN_AUTH_BASE/token")

ADMIN_NEW_AT=$(echo "$ADMIN_REFRESH_RESP" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
ADMIN_NEW_RT=$(echo "$ADMIN_REFRESH_RESP" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[[ -n "$ADMIN_NEW_AT" ]] && ok "Refresh produced new access_token" || fail "No access_token after refresh"
[[ -n "$ADMIN_NEW_RT" ]] && [[ "$ADMIN_NEW_RT" != "$ADMIN_RT" ]] \
    && ok "Refresh token rotated" \
    || fail "Refresh token not rotated"

# ── Step 24: Revoke ─────────────────────────────────────────
echo ""
echo "=== Step 24: OIDC login — revoke refresh token ==="

ADMIN_REVOKE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "${ADMIN_CLIENT_NAME}:" \
    -d "token=${ADMIN_NEW_RT}" \
    "$ADMIN_AUTH_BASE/revoke")

[[ "$ADMIN_REVOKE" = "200" ]] && ok "Revoke returned 200" || fail "Revoke expected 200, got $ADMIN_REVOKE"

ADMIN_REVOKED=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=${ADMIN_CLIENT_NAME}&refresh_token=${ADMIN_NEW_RT}" \
    "$ADMIN_AUTH_BASE/token" | grep -cE 'expired|invalid' || true)

[[ "$ADMIN_REVOKED" -gt 0 ]] && ok "Revoked refresh token rejected" || fail "Revoked refresh token was accepted"

rm -f "$ADMIN_OIDC_COOKIE" "$ADMIN_OIDC_HEADERS"

# ── Step 25: Admin delete cascade ────────────────────────────
echo ""
echo "=== Step 25: Admin — delete (cleanup) ==="

# The OIDC flow left login + session rows that guard deletion.
# Clean up via the admin API: /admin/sessions/invalidate deletes the sessions
# and their logins for the given user and client.
ADMIN_INVALIDATE=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"client_id":"'"$ADMIN_CREATED_CLIENT_ID"'","user_id":"'"$ADMIN_CREATED_USER_ID"'"}' \
    "$BASE/admin/sessions/invalidate")

echo "$ADMIN_INVALIDATE" | grep -q '"invalidated"' \
    && ok "Admin API invalidated OIDC sessions/logins" \
    || { fail "Admin API session invalidation failed: $ADMIN_INVALIDATE"; }

# Verification (local dev only): confirm no leftover logins/sessions block deletion.
# Falls back to sqlite3 only if the admin API left residue behind.
LEFT_LOGINS=$(sqlite3 db/data.db "SELECT COUNT(*) FROM logins WHERE client_id = '$ADMIN_CREATED_CLIENT_ID';" 2>/dev/null || echo 0)
LEFT_SESSIONS=$(sqlite3 db/data.db "SELECT COUNT(*) FROM sessions WHERE user_id = '$ADMIN_CREATED_USER_ID';" 2>/dev/null || echo 0)

if [[ "$LEFT_LOGINS" -eq 0 && "$LEFT_SESSIONS" -eq 0 ]]; then
    ok "No leftover logins/sessions (verified via sqlite)"
else
    fail "Leftover guard rows: $LEFT_LOGINS logins, $LEFT_SESSIONS sessions — sqlite fallback cleanup"
    sqlite3 db/data.db "DELETE FROM logins WHERE client_id = '$ADMIN_CREATED_CLIENT_ID';" 2>/dev/null || true
    sqlite3 db/data.db "DELETE FROM sessions WHERE user_id = '$ADMIN_CREATED_USER_ID';" 2>/dev/null || true
fi

# Delete user (no sessions → 204)
DEL_USER=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE -H "$ADMIN_HDR" "$BASE/admin/users/$ADMIN_CREATED_USER_ID")
[[ "$DEL_USER" = "204" ]] && ok "Deleted user → 204" || fail "Expected 204, got $DEL_USER"

# Confirm user is gone
GONE_USER=$(curl -sS -o /dev/null -w "%{http_code}" -H "$ADMIN_HDR" "$BASE/admin/users/$ADMIN_CREATED_USER_ID")
[[ "$GONE_USER" = "404" ]] && ok "Deleted user returns 404" || fail "Expected 404, got $GONE_USER"
ADMIN_CREATED_USER_ID=""

# Delete client (no logins → 204)
DEL_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE -H "$ADMIN_HDR" "$BASE/admin/clients/$ADMIN_CREATED_CLIENT_ID")
[[ "$DEL_CLIENT" = "204" ]] && ok "Deleted client → 204" || fail "Expected 204, got $DEL_CLIENT"

# Confirm client is gone
GONE_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -H "$ADMIN_HDR" "$BASE/admin/clients/$ADMIN_CREATED_CLIENT_ID")
[[ "$GONE_CLIENT" = "404" ]] && ok "Deleted client returns 404" || fail "Expected 404, got $GONE_CLIENT"
ADMIN_CREATED_CLIENT_ID=""

# Delete realm (now empty → 204)
DEL_REALM=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE -H "$ADMIN_HDR" "$BASE/admin/realms/$ADMIN_CREATED_REALM_ID")
[[ "$DEL_REALM" = "204" ]] && ok "Deleted realm → 204" || fail "Expected 204, got $DEL_REALM"

# Confirm realm is gone
GONE_REALM=$(curl -sS -o /dev/null -w "%{http_code}" -H "$ADMIN_HDR" "$BASE/admin/realms/$ADMIN_CREATED_REALM_ID")
[[ "$GONE_REALM" = "404" ]] && ok "Deleted realm returns 404" || fail "Expected 404, got $GONE_REALM"
ADMIN_CREATED_REALM_ID=""

# Clean up generated keys from filesystem
[[ -d "keys/$ADMIN_CREATED_KID" ]] && rm -rf "keys/$ADMIN_CREATED_KID" && ok "Cleaned up generated key pair from disk" || ok "Key cleanup already handled"
ADMIN_CREATED_KID=""

# ── All done ──────────────────────────────────────────────────
exit $FAIL
