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

ok()   { local msg="$1"; PASS=$((PASS+1)); echo "  ✓ $msg"; }
fail() { local msg="$1"; FAIL=$((FAIL+1)); echo "  ✗ $msg" >&2; }

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
echo "$CONFIG" | grep -q '"revocation_endpoint"' && ok "revocation_endpoint present" || fail "revocation_endpoint missing"

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

[[ -n "$LOGIN_ID" ]]   && ok "Extracted login_id: ${LOGIN_ID:0:8}..."   || { fail "login_id missing"; exit 1; }
[[ -n "$CSRF_TOKEN" ]] && ok "Extracted csrf_token: ${CSRF_TOKEN:0:8}..." || { fail "csrf_token missing"; exit 1; }

# ── Step 3: POST login (authenticate) ──────────────────────────
echo ""
echo "=== Step 3: POST login ==="
> "$HEADER_DUMP"
HTTP_CODE=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -D "$HEADER_DUMP" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=test@example.com&password=tst&csrf_token=${CSRF_TOKEN}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/login-actions/authenticate?q=${LOGIN_ID}")

if [[ "$HTTP_CODE" != "302" ]]; then
    fail "Login expected 302, got $HTTP_CODE"
    exit 1
fi
ok "Login returned 302 redirect"

LOCATION=$(grep -i '^location:' "$HEADER_DUMP" | sed 's/.*location: //I' | tr -d '\r\n')
AUTH_CODE=$(echo "$LOCATION" | sed 's/.*code=\([^&]*\).*/\1/')

if [[ -n "$AUTH_CODE" ]]; then
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

[[ -n "$ACCESS_TOKEN" ]] && ok "Got access_token"  || { fail "No access_token"; exit 1; }
[[ -n "$REFRESH_TOKEN" ]] && ok "Got refresh_token" || fail "No refresh_token"
[[ -n "$ID_TOKEN" ]]      && ok "Got id_token"      || fail "No id_token"
[[ "$TOKEN_TYPE" = "Bearer" ]] && ok "token_type is Bearer" || fail "token_type: $TOKEN_TYPE"

# ── Step 5: Introspect active tokens ────────────────────────────
echo ""
echo "=== Step 5: Introspect active tokens ==="
INTRO_ACCESS=$(curl -sS -X POST \
    -d "token=${ACCESS_TOKEN}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$INTRO_ACCESS" | grep -q '"active":true' && ok "Access token is active" || { fail "Access token not active"; exit 1; }
echo "$INTRO_ACCESS" | grep -q '"token_type":"Bearer"' && ok "token_type is Bearer" || fail "token_type not Bearer"

INTRO_REFRESH=$(curl -sS -X POST \
    -d "token=${REFRESH_TOKEN}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$INTRO_REFRESH" | grep -q '"active":true' && ok "Refresh token is active" || fail "Refresh token not active"
echo "$INTRO_REFRESH" | grep -q '"token_type":"refresh_token"' && ok "token_type is refresh_token" || fail "token_type not refresh_token"

INTRO_ID=$(curl -sS -X POST \
    -d "token=${ID_TOKEN}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$INTRO_ID" | grep -q '"active":true' && ok "ID token is active" || fail "ID token not active"
echo "$INTRO_ID" | grep -q '"token_type":"ID"' && ok "token_type is ID" || fail "token_type not ID"

# ── Step 6: GET /certs (JWKS) ──────────────────────────────────
echo ""
echo "=== Step 5: GET /certs ==="
CERTS=$(curl -sf "$BASE_URL/realms/$REALM/protocol/openid-connect/certs") || {
    fail "Certs endpoint unreachable"
    exit 1
}
echo "$CERTS" | grep -q '"keys"' && ok "/certs returns keys" || fail "/certs missing keys array"

# ── Step 7: GET /userinfo ──────────────────────────────────────
echo ""
echo "=== Step 6: GET /userinfo ==="
USERINFO=$(curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/userinfo") || {
    fail "Userinfo endpoint unreachable"
    exit 1
}
echo "$USERINFO" | grep -q '"sub"' && ok "Userinfo returns sub" || fail "Userinfo missing sub"

# ── Step 8: Refresh token ──────────────────────────────────────
echo ""
echo "=== Step 7: Refresh token ==="
REFRESH_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=$CLIENT&refresh_token=${REFRESH_TOKEN}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")

NEW_ACCESS=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
NEW_REFRESH=$(echo "$REFRESH_RESPONSE" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[[ -n "$NEW_ACCESS" ]] && ok "Refresh produced new access_token" || fail "No access_token after refresh"
[[ -n "$NEW_REFRESH" ]] && [[ "$NEW_REFRESH" != "$REFRESH_TOKEN" ]] \
    && ok "Refresh token rotated" \
    || fail "Refresh token not rotated"

# ── Step 9: 3p-cookies pages & login-status-iframe ─────────────
echo ""
echo "=== Step 8: 3p-cookies pages & login-status-iframe ==="
for step in step1.html step2.html; do
    HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
        "$BASE_URL/realms/$REALM/protocol/openid-connect/3p-cookies/$step")
    if [[ "$HTTP_CODE" = "200" ]]; then
        ok "3p-cookies/$step returns 200"
    else
        fail "3p-cookies/$step returned $HTTP_CODE"
    fi
done

HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/login-status-iframe.html")
[[ "$HTTP_CODE" = "200" ]] && ok "login-status-iframe.html returns 200" || fail "login-status-iframe.html returned $HTTP_CODE"

# ── Step 10: Revoke refresh token ─────────────────────────────
echo ""
echo "=== Step 9: Revoke refresh token ==="
REVOKE_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "token=${NEW_REFRESH}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/revoke")

[[ "$REVOKE_CODE" = "200" ]] && ok "Revoke returns 200" || { fail "Revoke expected 200, got $REVOKE_CODE"; exit 1; }

USED_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=$CLIENT&refresh_token=${NEW_REFRESH}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token" \
    | grep -cE 'expired|invalid' || true)

[[ "$USED_REFRESH" -gt 0 ]] && ok "Revoked refresh token rejected" || fail "Revoked refresh token was accepted"

# ── Step 11: Revoke access token ─────────────────────────────
echo ""
echo "=== Step 10: Revoke access token ==="
REVOKE_AT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "token_type_hint=access_token&token=${NEW_ACCESS}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/revoke")

[[ "$REVOKE_AT" = "200" ]] && ok "Revoke access token returns 200" || { fail "Revoke access token expected 200, got $REVOKE_AT"; exit 1; }

USERINFO_CHECK=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${NEW_ACCESS}" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/userinfo")

[[ "$USERINFO_CHECK" = "401" ]] && ok "Revoked access token rejected at userinfo" || fail "Revoked access token was accepted at userinfo (got $USERINFO_CHECK)"

# ── Step 12: Client Credentials grant ───────────────────────────
echo ""
echo "=== Step 12: Client Credentials grant ==="
CC_RESPONSE=$(curl -sS -X POST \
    -d "grant_type=client_credentials&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")

CC_ACCESS=$(echo "$CC_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
CC_SCOPE=$(echo "$CC_RESPONSE" | sed -n 's/.*"scope":"\([^"]*\)".*/\1/p')

[[ -n "$CC_ACCESS" ]] && ok "Got client_credentials access_token" || { fail "No access_token"; exit 1; }
echo "$CC_RESPONSE" | grep -q '"refresh_token"' && fail "client_credentials should not issue refresh_token" || ok "No refresh_token issued"
echo "$CC_RESPONSE" | grep -q '"id_token"' && fail "client_credentials should not issue id_token" || ok "No id_token issued"
[[ -n "$CC_SCOPE" ]] && ok "Scope: $CC_SCOPE" || fail "No scope in response"

CC_INTRO=$(curl -sS -X POST \
    -d "token=${CC_ACCESS}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$CC_INTRO" | grep -q '"active":true' && ok "client_credentials token is active" || { fail "client_credentials token not active"; exit 1; }

# ── Step 13: Introspect revoked & garbage tokens ────────────────
echo ""
echo "=== Step 13: Introspect revoked & garbage tokens ==="

INTRO_REVOKED=$(curl -sS -X POST \
    -d "token=${NEW_ACCESS}&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$INTRO_REVOKED" | grep -q '"active":false' && ok "Revoked access token shows inactive" || fail "Revoked access token should be inactive"

INTRO_GARBAGE=$(curl -sS -X POST \
    -d "token=not-a-jwt&client_id=$CLIENT" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

echo "$INTRO_GARBAGE" | grep -q '"active":false' && ok "Garbage token is not active" || fail "Garbage token should not be active"

BAD_AUTH_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "token=${NEW_ACCESS}&client_id=nonexistent" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect")

[[ "$BAD_AUTH_CODE" = "401" ]] && ok "Bad client returns 401" || fail "Bad client expected 401, got $BAD_AUTH_CODE"

# ── Step 14: prompt=none (no session) ────────────────────────
echo ""
echo "=== Step 14: prompt=none (no session) ==="
# Only the no-session branch is checked: silent auth depends on the
# Secure AUTH_SESSION cookie reaching the server, which can fail for
# infra reasons unrelated to the code. That case is covered by the
# PHPUnit integration test (FullFlowTest::testPromptNoneWithValidSessionReturnsCode).
PN_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/auth?client_id=$CLIENT&redirect_uri=$REDIRECT_URI&response_type=code&response_mode=query&scope=openid&state=e2e-pn&nonce=e2e-pn&prompt=none"

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

# ── Step 15: Logout redirect validation ──────────────────────
echo ""
echo "=== Step 15: Logout redirect validation ==="
NEG_REDIRECT_URI="https://evil.com"

> "$HEADER_DUMP"
LG_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -D "$HEADER_DUMP" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/logout?id_token_hint=${ID_TOKEN}&post_logout_redirect_uri=$REDIRECT_URI")

[[ "$LG_CODE" = "302" ]] && ok "Logout to registered uri returns 302" || { fail "Logout expected 302, got $LG_CODE"; exit 1; }

LG_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)
echo "$LG_LOCATION" | grep -q "$REDIRECT_URI" \
    && ok "Logout redirects to registered uri" \
    || fail "Logout did not redirect to registered uri: $LG_LOCATION"

> "$HEADER_DUMP"
LG_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -D "$HEADER_DUMP" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/logout?id_token_hint=${ID_TOKEN}&post_logout_redirect_uri=${NEG_REDIRECT_URI}")

LG_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)

if echo "$LG_LOCATION" | grep -q "$NEG_REDIRECT_URI"; then
    fail "Logout redirected to unregistered uri"
else
    ok "Logout does not redirect to unregistered uri"
fi

exit $FAIL
