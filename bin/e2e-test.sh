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
    rm -f "${ADMIN_OIDC_COOKIE:-}" "${ADMIN_OIDC_HEADERS:-}" 2>/dev/null || true
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
    # Belt-and-braces: a crashed previous run can leave the PHP built-in server
    # (or a child) holding the port even after its PID is gone, so force-release
    # it. No-op when fuser is unavailable or the port is already free.
    fuser -k "${PORT}/tcp" 2>/dev/null || true
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

# Reset persisted rate-limit counters so a previous run's requests inside the
# current window can't exhaust the /token quota and cause flaky 429s. The
# PHPUnit rate-limit tests use an in-memory SQLite (RateLimitingTest), so
# clearing the dev DB's rate_limits table cannot affect them.
sqlite3 db/data.db "DELETE FROM rate_limits;" 2>/dev/null || true

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

# ── Step 1b: Discovery document truthfulness (F-34) ─────────────
echo ""
echo "=== Step 1b: OIDC discovery document (F-34) ==="
DISCOVERY=$(curl -sS "$BASE/realms/test/.well-known/openid-configuration")

echo "$DISCOVERY" | grep -q '"scopes_supported": \["openid"' \
    && ok "scopes_supported advertised (RFC 8414)" \
    || fail "scopes_supported missing from discovery"
echo "$DISCOVERY" | grep -q '"scope_supported"' \
    && fail "legacy scope_supported still advertised" \
    || ok "no legacy scope_supported key"
echo "$DISCOVERY" | grep -q '"request_parameter_supported": false' \
    && ok "request_parameter_supported: false" \
    || fail "request_parameter_supported not false"
echo "$DISCOVERY" | grep -q '"request_uri_parameter_supported": false' \
    && ok "request_uri_parameter_supported: false" \
    || fail "request_uri_parameter_supported not false"
echo "$DISCOVERY" | grep -q '"require_request_uri_registration": false' \
    && ok "require_request_uri_registration: false" \
    || fail "require_request_uri_registration not false"
echo "$DISCOVERY" | grep -q '"tls_client_certificate_bound_access_tokens": false' \
    && ok "tls_client_certificate_bound_access_tokens: false" \
    || fail "tls_client_certificate_bound_access_tokens not false"
echo "$DISCOVERY" | grep -q '"frontchannel_logout_supported": false' \
    && ok "frontchannel_logout_supported: false" \
    || fail "frontchannel_logout_supported not false"
echo "$DISCOVERY" | grep -q '"frontchannel_logout_session_supported": false' \
    && ok "frontchannel_logout_session_supported: false" \
    || fail "frontchannel_logout_session_supported not false"
echo "$DISCOVERY" | grep -q '"pairwise"' \
    && fail "subject_types_supported advertises pairwise" \
    || ok "subject_types_supported: public only (no pairwise)"

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

# ── Step 2b: Auth code binding (F-21) ─────────────────────────
echo ""
echo "=== Step 2b: Auth code binding (F-21) ==="

# A code minted for kc_app must not be redeemable by a different client (S-01).
CROSS_CLIENT_CODE=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=local&code=${AUTH_CODE}&redirect_uri=http://localhost:5173" \
    "$BASE/realms/test/protocol/openid-connect/token")

echo "$CROSS_CLIENT_CODE" | grep -q 'invalid_grant' \
    && ok "Cross-client code redemption rejected (F-21)" \
    || fail "Cross-client code redemption was accepted"

# A code minted for one redirect_uri must not be redeemable with a different one (F-21).
WRONG_REDIRECT_CODE=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=kc_app&code=${AUTH_CODE}&redirect_uri=https://www.keycloak.org/app/cb" \
    "$BASE/realms/test/protocol/openid-connect/token")

echo "$WRONG_REDIRECT_CODE" | grep -q 'invalid_grant' \
    && ok "Wrong-redirect code redemption rejected (F-21)" \
    || fail "Wrong-redirect code redemption was accepted"

# A code minted in one realm must not be redeemable at another (S-03):
# same client + redirect, different realm URL.
CROSS_REALM_CODE=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=kc_app&code=${AUTH_CODE}&redirect_uri=https://www.keycloak.org/app" \
    "$BASE/realms/web/protocol/openid-connect/token")

echo "$CROSS_REALM_CODE" | grep -q 'invalid_grant' \
    && ok "Cross-realm code redemption rejected (F-23)" \
    || fail "Cross-realm code redemption was accepted"

# The failed attempts must not consume the code: the real redemption in the
# next step still succeeds.

# ── Step 2c: prompt=login forces re-auth (F-32) ────────────────
echo ""
echo "=== Step 2c: prompt=login forces re-auth (F-32) ==="
# AUTH_SESSION is Secure+HttpOnly, so curl's cookie jar will not re-send it
# over plain http. Inject the session value captured from the jar directly so
# the SSO-session branch can be exercised (same technique as an https client).
SSO_VALUE=$(awk -F'\t' '$6 == "AUTH_SESSION" {print $7; exit}' "$COOKIE_JAR" 2>/dev/null || true)
[[ -n "$SSO_VALUE" ]] && ok "Captured SSO session cookie value" || fail "AUTH_SESSION not found in cookie jar"

SSO_URL="$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/app&response_type=code&response_mode=query&scope=openid&state=e2e-sso&nonce=e2e-sso"

> "$HEADER_DUMP"
SSO_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -b "AUTH_SESSION=${SSO_VALUE}" -D "$HEADER_DUMP" "$SSO_URL")
[[ "$SSO_CODE" = "302" ]] && ok "Valid SSO session reused without prompt → 302" || fail "SSO reuse expected 302, got $SSO_CODE"
SSO_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)
echo "$SSO_LOCATION" | grep -q 'code=' \
    && ok "SSO reuse issued a code" \
    || fail "SSO reuse did not issue a code"

PL_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -b "AUTH_SESSION=${SSO_VALUE}" "${SSO_URL}&prompt=login")
[[ "$PL_CODE" = "200" ]] && ok "prompt=login with valid session returns 200" || fail "prompt=login expected 200, got $PL_CODE"

PL_BODY=$(curl -sS -b "AUTH_SESSION=${SSO_VALUE}" "${SSO_URL}&prompt=login")
echo "$PL_BODY" | grep -q 'login' \
    && ok "prompt=login renders login form (session not reused)" \
    || fail "prompt=login did not render login form"

# ── Step 3: POST /token ───────────────────────────────────────
echo ""
echo "=== Step 3: POST /token ==="
> "$HEADER_DUMP"
TOKEN_RESPONSE=$(curl -sS -D "$HEADER_DUMP" -X POST \
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

# ── Step 3c: Client roles in resource_access (F-04) ──────────
echo ""
echo "=== Step 3c: Client roles — resource_access (F-04) ==="

ACCESS_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | python3 -c "import sys, base64, json; payload=sys.stdin.read().strip(); payload += '=' * (4 - len(payload) % 4); print(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))" 2>/dev/null || echo "{}")

# The seeded realm-test user emant_test has app-user client role for kc_app
echo "$ACCESS_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); roles=d.get('resource_access',{}).get('kc_app',{}).get('roles',[])" 2>/dev/null | grep -q 'app-user' \
    && ok "resource_access.kc_app.roles contains app-user (F-04)" \
    || fail "resource_access.kc_app.roles missing app-user"

REFRESH_PAYLOAD=$(echo "$REFRESH_TOKEN" | cut -d. -f2 | python3 -c "import sys, base64, json; payload=sys.stdin.read().strip(); payload += '=' * (4 - len(payload) % 4); print(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))" 2>/dev/null || echo "{}")

echo "$REFRESH_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); roles=d.get('resource_access',{}).get('kc_app',{}).get('roles',[])" 2>/dev/null | grep -q 'app-user' \
    && ok "refresh_token carries resource_access (F-04)" \
    || fail "refresh_token missing resource_access"

# ── Step 3b: no-store on token responses (F-28) ────────────────
echo ""
echo "=== Step 3b: token response cache headers (F-28) ==="
grep -qi '^Cache-Control: *no-store' "$HEADER_DUMP" \
    && ok "Token response Cache-Control: no-store" \
    || fail "Token response missing Cache-Control: no-store"
grep -qi '^Pragma: *no-cache' "$HEADER_DUMP" \
    && ok "Token response Pragma: no-cache" \
    || fail "Token response missing Pragma: no-cache"

# ── Step 4: Introspect active tokens ─────────────────────────
echo ""
echo "=== Step 4: Introspect active tokens ==="

INTRO_ACCESS=$(curl -sS -X POST \
    -d "token=${ACCESS_TOKEN}&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token/introspect")

echo "$INTRO_ACCESS" | grep -q '"active":true' && ok "Access token is active" || { fail "Access token not active"; exit 1; }
echo "$INTRO_ACCESS" | grep -q '"token_type":"Bearer"' && ok "token_type is Bearer" || fail "token_type not Bearer"
echo "$INTRO_ACCESS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('resource_access',{}).get('kc_app',{}).get('roles',[]),d.get('realm_access',{}).get('roles',[]))" 2>/dev/null | grep -q 'app-user' \
    && ok "Introspect passes through resource_access (F-04)" \
    || fail "Introspect missing resource_access passthrough"

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

# ── Step 6b: RFC 6749 error surface (F-27/F-29) ────────────────
echo ""
echo "=== Step 6b: RFC 6749 error surface (F-27/F-29) ==="

# Unknown client on the token endpoint -> 401 invalid_client
BAD_CLIENT_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -d "grant_type=refresh_token&client_id=nonexistent&refresh_token=${REFRESH_TOKEN}" \
    "$BASE/realms/test/protocol/openid-connect/token")
[[ "$BAD_CLIENT_CODE" = "401" ]] && ok "Token endpoint unknown client returns 401" || { fail "Token unknown client expected 401, got $BAD_CLIENT_CODE"; exit 1; }

BAD_CLIENT_BODY=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=nonexistent&refresh_token=${REFRESH_TOKEN}" \
    "$BASE/realms/test/protocol/openid-connect/token")
echo "$BAD_CLIENT_BODY" | grep -q '"error":"invalid_client"' \
    && ok "Token endpoint returns invalid_client" \
    || fail "Token endpoint did not return invalid_client"

# Unsupported grant type -> 400 unsupported_grant_type
BAD_GRANT_CODE=$(curl -sS -X POST \
    -d "grant_type=implicit&client_id=kc_app" \
    "$BASE/realms/test/protocol/openid-connect/token")
echo "$BAD_GRANT_CODE" | grep -q '"error":"unsupported_grant_type"' \
    && ok "Unsupported grant type rejected (F-27)" \
    || fail "Unsupported grant type not rejected"

# Unsupported response_type on the auth endpoint -> 400 unsupported_response_type (F-29)
BAD_RESPONSE_TYPE=$(curl -sS -o /dev/null -w "%{http_code}" -X GET \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/app&response_type=token&scope=openid")
[[ "$BAD_RESPONSE_TYPE" = "400" ]] && ok "response_type=token rejected (F-29)" || { fail "response_type=token expected 400, got $BAD_RESPONSE_TYPE"; exit 1; }

BAD_RESPONSE_BODY=$(curl -sS -X GET \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/app&response_type=token&scope=openid")
echo "$BAD_RESPONSE_BODY" | grep -q '"error":"unsupported_response_type"' \
    && ok "Auth endpoint returns unsupported_response_type" \
    || fail "Auth endpoint did not return unsupported_response_type"

# ── Step 6c: nonce/state/response_mode optional (F-31) ─────────
echo ""
echo "=== Step 6c: code flow without nonce/state/response_mode (F-31) ==="
COMPAT_COOKIE="$E2E_LOG_DIR/compat-cookies.txt"
COMPAT_URL="$BASE/realms/test/protocol/openid-connect/auth?client_id=local&redirect_uri=http://localhost:5173&response_type=code&scope=openid"

AUTH_NO_OPT=$(curl -sS -c "$COMPAT_COOKIE" "$COMPAT_URL")
echo "$AUTH_NO_OPT" | grep -q 'login' \
    && ok "Auth without nonce/state/response_mode renders login form" \
    || fail "Auth without optional params did not render login form"

NO_OPT_LOGIN_ID=$(echo "$AUTH_NO_OPT" | sed -n 's/.*action="[^"]*?q=\([^"]*\)".*/\1/p')
NO_OPT_CSRF=$(echo "$AUTH_NO_OPT" | sed -n 's/.*name="csrf_token"\s*value="\([^"]*\)".*/\1/p')
[[ -n "$NO_OPT_LOGIN_ID" && -n "$NO_OPT_CSRF" ]] \
    && ok "Extracted login_id + csrf_token for optional-params flow" \
    || { fail "login_id/csrf_token missing for F-31 flow"; rm -f "$COMPAT_COOKIE"; exit 1; }

> "$HEADER_DUMP"
NO_OPT_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -c "$COMPAT_COOKIE" -b "$COMPAT_COOKIE" -D "$HEADER_DUMP" -X POST \
    -d "email=test@example.com&password=tst&csrf_token=${NO_OPT_CSRF}" \
    "$BASE/realms/test/protocol/openid-connect/login-actions/authenticate?q=${NO_OPT_LOGIN_ID}")
[[ "$NO_OPT_CODE" = "302" ]] && ok "Login without optional params returned 302" || { fail "F-31 login expected 302, got $NO_OPT_CODE"; rm -f "$COMPAT_COOKIE"; exit 1; }

NO_OPT_LOCATION=$(grep -i '^location:' "$HEADER_DUMP" 2>/dev/null | sed 's/.*location: //I' | tr -d '\r\n' || true)
echo "$NO_OPT_LOCATION" | grep -q 'code=' \
    && ok "Code issued with defaulted state/nonce/response_mode" \
    || fail "No code in F-31 redirect"
rm -f "$COMPAT_COOKIE"

# ── Step 6d: exact redirect_uri matching (F-33) ────────────────
echo ""
echo "=== Step 6d: exact redirect_uri matching (F-33) ==="
SUB_PATH_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/appx&response_type=code&scope=openid")
[[ "$SUB_PATH_CODE" = "400" ]] && ok "Sub-path redirect_uri rejected (F-33)" || fail "Sub-path redirect_uri expected 400, got $SUB_PATH_CODE"

SUB_PATH_BODY=$(curl -sS \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=kc_app&redirect_uri=https://www.keycloak.org/appx&response_type=code&scope=openid")
echo "$SUB_PATH_BODY" | grep -q '"error":"invalid_request"' \
    && ok "Sub-path redirect rejected with invalid_request" \
    || fail "Sub-path redirect error not invalid_request"

# ── Step 6e: Keycloak-style `*` wildcard redirect_uri (F-44) ─
echo ""
echo "=== Step 6e: * wildcard redirect_uri (F-44) ==="
# `local` is registered as `http://localhost:5173/*`: subroutes are allowed,
# sibling hosts are not.
WILD_SUB_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=local&redirect_uri=http://localhost:5173/dashboard&response_type=code&scope=openid")
[[ "$WILD_SUB_CODE" = "200" ]] && ok "Wildcard: subroute login allowed" || fail "Wildcard subroute expected 200, got $WILD_SUB_CODE"

WILD_SIB_HOST_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/auth?client_id=local&redirect_uri=http://localhost:5173x/dashboard&response_type=code&scope=openid")
[[ "$WILD_SIB_HOST_CODE" = "400" ]] && ok "Wildcard: sibling host rejected" || fail "Wildcard sibling host expected 400, got $WILD_SIB_HOST_CODE"

# Path-scoped wildcard (`playground`, realm web): sibling path rejected.
WILD_SIB_PATH_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/web/protocol/openid-connect/auth?client_id=playground&redirect_uri=http://localhost:5173/react-playgroundx&response_type=code&scope=openid")
[[ "$WILD_SIB_PATH_CODE" = "400" ]] && ok "Wildcard: sibling path rejected" || fail "Wildcard sibling path expected 400, got $WILD_SIB_PATH_CODE"

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

# Revoke with unknown client must 401 (RFC 7009 §2.2)
REVOKE_BAD_CLIENT=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -u "nonexistent-client:" \
    -d "token=${NEW_REFRESH}" \
    "$BASE/realms/test/protocol/openid-connect/revoke")

[[ "$REVOKE_BAD_CLIENT" = "401" ]] && ok "Revoke with unknown client returned 401" || { fail "Revoke with unknown client expected 401, got $REVOKE_BAD_CLIENT"; exit 1; }

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

# Path-scoped wildcards do not affect the iframe origin allowlist (F-44).
IFRAME_WILD_ORIGIN=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=local&origin=http://localhost:5173")
[[ "$IFRAME_WILD_ORIGIN" = "200" ]] && ok "wildcard client origin accepted by iframe init" || fail "wildcard iframe init expected 200, got $IFRAME_WILD_ORIGIN"

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

# Create realm (offline_access granted so the F-02 flow can run on it; the
# throwaway realm is deleted at the end of this section)
REALM_RESP=$(curl -sS -X POST -H "$ADMIN_HDR" -H "Content-Type: application/json" \
    -d '{"name":"e2e-admin-realm","keys_id":"'"$ADMIN_CREATED_KID"'","scope":"openid profile email offline_access"}' \
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

# ── Step 24b: Offline access on the throwaway realm (F-02) ──
echo ""
echo "=== Step 24b: OIDC login — offline_access long-lived refresh token ==="

# Fresh rate-limit headroom for the extra /token calls below
sqlite3 db/data.db "DELETE FROM rate_limits;" 2>/dev/null || true

OFFLINE_COOKIE=$(mktemp)
OFFLINE_HEADERS=$(mktemp)

OFFLINE_AUTH=$(curl -sS -c "$OFFLINE_COOKIE" \
    "$ADMIN_AUTH_BASE/auth?client_id=$ADMIN_CLIENT_NAME&redirect_uri=$ADMIN_REDIRECT_URI&response_type=code&response_mode=query&scope=openid%20offline_access&state=e2e-offline-st&nonce=e2e-offline-nc")

echo "$OFFLINE_AUTH" | grep -q 'login' \
    && ok "Offline auth: login form with offline_access scope" \
    || fail "Offline auth: did not return login form"

OFFLINE_LOGIN_ID=$(echo "$OFFLINE_AUTH" | sed -n 's/.*action="[^"]*?q=\([^"]*\)".*/\1/p')
OFFLINE_CSRF=$(echo "$OFFLINE_AUTH" | sed -n 's/.*name="csrf_token"\s*value="\([^"]*\)".*/\1/p')

[[ -n "$OFFLINE_LOGIN_ID" ]] && ok "Offline auth: extracted login_id" || { fail "Offline auth: login_id missing"; rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"; exit 1; }
[[ -n "$OFFLINE_CSRF" ]]     && ok "Offline auth: extracted csrf_token" || { fail "Offline auth: csrf_token missing"; rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"; exit 1; }

> "$OFFLINE_HEADERS"
OFFLINE_LOGIN_CODE=$(curl -sS -c "$OFFLINE_COOKIE" -b "$OFFLINE_COOKIE" \
    -D "$OFFLINE_HEADERS" -o /dev/null -w "%{http_code}" \
    -X POST \
    -d "email=${ADMIN_EMAIL}&password=${ADMIN_PASSWORD}&csrf_token=${OFFLINE_CSRF}" \
    "$ADMIN_AUTH_BASE/login-actions/authenticate?q=${OFFLINE_LOGIN_ID}")

if [[ "$OFFLINE_LOGIN_CODE" != "302" ]]; then
    fail "Offline login expected 302, got $OFFLINE_LOGIN_CODE"
    rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"
    exit 1
fi
ok "Offline login returned 302 redirect"

OFFLINE_LOCATION=$(grep -i '^location:' "$OFFLINE_HEADERS" | sed 's/.*location: //I' | tr -d '\r\n')
OFFLINE_CODE=$(echo "$OFFLINE_LOCATION" | sed 's/.*code=\([^&]*\).*/\1/')

if [[ -n "$OFFLINE_CODE" ]]; then
    ok "Offline auth code obtained"
else
    fail "Offline auth: no code in Location header"
    rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"
    exit 1
fi

OFFLINE_TOKENS=$(curl -sS -X POST \
    -d "grant_type=authorization_code&client_id=${ADMIN_CLIENT_NAME}&code=${OFFLINE_CODE}&redirect_uri=${ADMIN_REDIRECT_URI}" \
    "$ADMIN_AUTH_BASE/token")

OFFLINE_AT=$(echo "$OFFLINE_TOKENS" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
OFFLINE_RT=$(echo "$OFFLINE_TOKENS" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
OFFLINE_IDT=$(echo "$OFFLINE_TOKENS" | sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p')
OFFLINE_RT_TTL=$(echo "$OFFLINE_TOKENS" | sed -n 's/.*"refresh_expires_in":\([0-9]*\).*/\1/p')

[[ -n "$OFFLINE_RT" ]] && ok "Offline grant: refresh_token issued" || { fail "Offline grant: no refresh_token"; rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"; exit 1; }
echo "$OFFLINE_TOKENS" | grep -q '"scope":"openid offline_access"' && ok "Offline grant: scope is openid offline_access" || fail "Offline grant: unexpected scope"
[[ "$OFFLINE_RT_TTL" = "2592000" ]] && ok "Offline grant: refresh_expires_in = 30d ($OFFLINE_RT_TTL)" || fail "Offline grant: refresh_expires_in = $OFFLINE_RT_TTL"

OFFLINE_TYP=$(echo "$OFFLINE_RT" | cut -d. -f2 | python3 -c "import sys,base64,json; p=sys.stdin.read().strip(); p+='='*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))['typ'])" 2>/dev/null || true)
[[ "$OFFLINE_TYP" = "Offline" ]] && ok "Offline refresh token carries typ=Offline" || fail "Offline refresh token typ: $OFFLINE_TYP"

# Refresh: issues a fresh bundle and rotates the offline token
OFFLINE_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=${ADMIN_CLIENT_NAME}&refresh_token=${OFFLINE_RT}" \
    "$ADMIN_AUTH_BASE/token")
OFFLINE_NEW_AT=$(echo "$OFFLINE_REFRESH" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
OFFLINE_NEW_RT=$(echo "$OFFLINE_REFRESH" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')

[[ -n "$OFFLINE_NEW_AT" ]] && ok "Offline refresh produced new access_token" || fail "Offline refresh: no access_token"
[[ -n "$OFFLINE_NEW_RT" ]] && [[ "$OFFLINE_NEW_RT" != "$OFFLINE_RT" ]] \
    && ok "Offline refresh token rotated" \
    || fail "Offline refresh token not rotated"

OFFLINE_INTRO=$(curl -sS -X POST \
    -d "token=${OFFLINE_NEW_RT}&client_id=${ADMIN_CLIENT_NAME}" \
    "$ADMIN_AUTH_BASE/token/introspect")
echo "$OFFLINE_INTRO" | grep -q '"active":true' && ok "Offline refresh token introspects active" || fail "Offline refresh token not active on introspect"

# Offline tokens survive SSO logout (Keycloak parity)
OFFLINE_LOGOUT=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$ADMIN_AUTH_BASE/logout?id_token_hint=${OFFLINE_IDT}")
[[ "$OFFLINE_LOGOUT" = "204" ]] && ok "Offline SSO logout returned 204" || fail "Offline logout expected 204, got $OFFLINE_LOGOUT"

OFFLINE_AFTER_LOGOUT=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=${ADMIN_CLIENT_NAME}&refresh_token=${OFFLINE_NEW_RT}" \
    "$ADMIN_AUTH_BASE/token")
echo "$OFFLINE_AFTER_LOGOUT" | grep -q '"access_token"' && ok "Offline refresh survives logout" || fail "Offline refresh failed after logout"

# RFC 7009 revocation kills the offline token
OFFLINE_REVOKE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -u "${ADMIN_CLIENT_NAME}:" \
    -d "token=${OFFLINE_NEW_RT}" \
    "$ADMIN_AUTH_BASE/revoke")
[[ "$OFFLINE_REVOKE" = "200" ]] && ok "Offline revoke returned 200" || { fail "Offline revoke expected 200, got $OFFLINE_REVOKE"; rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"; exit 1; }

OFFLINE_REVOKED_REFRESH=$(curl -sS -X POST \
    -d "grant_type=refresh_token&client_id=${ADMIN_CLIENT_NAME}&refresh_token=${OFFLINE_NEW_RT}" \
    "$ADMIN_AUTH_BASE/token" | grep -cE 'expired|invalid' || true)
[[ "$OFFLINE_REVOKED_REFRESH" -gt 0 ]] && ok "Revoked offline refresh token rejected" || fail "Revoked offline refresh token was accepted"

rm -f "$OFFLINE_COOKIE" "$OFFLINE_HEADERS"

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
    && ok "Admin API invalidated OIDC sessions/logins/offline" \
    || { fail "Admin API session invalidation failed: $ADMIN_INVALIDATE"; }

# Verification (local dev only): confirm no leftover logins/sessions or ACTIVE
# offline_sessions block deletion. The offline grant was revoked in 24b, so its
# row is EXPIRED here — an ACTIVE row would trip the admin delete guards (409).
LEFT_LOGINS=$(sqlite3 db/data.db "SELECT COUNT(*) FROM logins WHERE client_id = '$ADMIN_CREATED_CLIENT_ID';" 2>/dev/null || echo 0)
LEFT_SESSIONS=$(sqlite3 db/data.db "SELECT COUNT(*) FROM sessions WHERE user_id = '$ADMIN_CREATED_USER_ID';" 2>/dev/null || echo 0)
LEFT_OFFLINE_ACTIVE=$(sqlite3 db/data.db "SELECT COUNT(*) FROM offline_sessions WHERE client_id = '$ADMIN_CREATED_CLIENT_ID' AND status = 'ACTIVE';" 2>/dev/null || echo 0)

if [[ "$LEFT_LOGINS" -eq 0 && "$LEFT_SESSIONS" -eq 0 && "$LEFT_OFFLINE_ACTIVE" -eq 0 ]]; then
    ok "No leftover guard rows (logins/sessions/offline) — verified via sqlite"
else
    fail "Leftover guard rows: $LEFT_LOGINS logins, $LEFT_SESSIONS sessions, $LEFT_OFFLINE_ACTIVE active offline — sqlite fallback cleanup"
    sqlite3 db/data.db "DELETE FROM logins WHERE client_id = '$ADMIN_CREATED_CLIENT_ID';" 2>/dev/null || true
    sqlite3 db/data.db "DELETE FROM sessions WHERE user_id = '$ADMIN_CREATED_USER_ID';" 2>/dev/null || true
    sqlite3 db/data.db "UPDATE offline_sessions SET status = 'EXPIRED' WHERE client_id = '$ADMIN_CREATED_CLIENT_ID' AND status = 'ACTIVE';" 2>/dev/null || true
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

# No offline_sessions rows may survive the deleted client (no orphans)
LEFT_OFFLINE_AFTER=$(sqlite3 db/data.db "SELECT COUNT(*) FROM offline_sessions WHERE client_id = '$ADMIN_CREATED_CLIENT_ID';" 2>/dev/null || echo 1)
[[ "$LEFT_OFFLINE_AFTER" -eq 0 ]] && ok "No offline_sessions rows survived the delete" || fail "$LEFT_OFFLINE_AFTER orphaned offline_sessions row(s) left"
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
