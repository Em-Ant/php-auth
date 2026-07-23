# Revocation Endpoint (RFC 7009)

[x] - Status: *DONE* - 07/24/2026 00:34

Add `POST /realms/{realm}/protocol/openid-connect/revoke` so clients can revoke
access and refresh tokens.

---

## Database

Add migration `002_token_blacklist.up.sql`:

```sql
CREATE TABLE token_blacklist (
    jti TEXT PRIMARY KEY,
    exp INTEGER NOT NULL,      -- token's original exp claim (for cleanup)
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_token_blacklist_exp ON token_blacklist(exp);
```

Migration `002_token_blacklist.down.sql`:

```sql
DROP TABLE IF EXISTS token_blacklist;
```

---

## Endpoint: `POST /revoke`

### Request

| Field | Required | Description |
|---|---|---|
| `token` | yes | The token string to revoke |
| `token_type_hint` | no | `access_token` or `refresh_token` |

Client authentication is the same as the token endpoint (uses client credentials).

### Behaviour

1. Validate client credentials (same as `POST /token`).
2. If `token_type_hint` is absent or `refresh_token`, try to look up the token in
   `logins.refresh_token` first:
   - If found and owned by the requesting client, set login status to `EXPIRED` and
     also kill the associated session (`sessions.status = EXPIRED`).
   - If not found, treat it as an access token.
3. If `token_type_hint` is `access_token` (or fallback from step 2):
   - Decode the JWT without verifying the signature first (to extract `jti` and `exp`).
   - Verify it was issued to the requesting client (`aud` or `client_id` claim matches).
   - Verify the signature via `TokenService::validateToken()`.
   - Insert `jti` into `token_blacklist`.
4. Always return **`200 OK`** with empty JSON body `{}`.

### Error cases

| Situation | Response |
|---|---|
| Client auth fails | `401 Unauthorized` |
| Token cannot be decoded (malformed JWT) | `200 OK` (no-op) |
| Token was not issued to this client | `200 OK` (no-op) |
| Token signature invalid | `200 OK` (no-op) |
| Token already revoked / expired | `200 OK` (no-op) |

RFC 7009 mandates **silent failure** for all token-level errors — only bad client
auth produces an error response.

---

## ValidateAccessToken middleware

Update `ValidateAccessToken` to also check `token_blacklist` after signature
validation. If the `jti` is found in the blacklist, respond `401 Unauthorized`.

---

## Well-known config

Update the `OidcController::sendConfig` discovery document to expose:

```php
'revocation_endpoint' => $issuer . '/protocol/openid-connect/revoke',
'revocation_endpoint_auth_methods_supported' => ['client_secret_basic'],
```

---

## Verification checklist

Run against the dev server (`composer serve`) with a real OIDC flow using curl.
The **e2e test** (`bin/e2e-test.sh`) already does the auth → login → token →
refresh dance; you can reuse its setup.

### 1. Revoke a refresh token

```
# Full OIDC flow to get tokens
# ... (call /auth, POST /login-actions/authenticate, POST /token)

# Revoke the refresh token
curl -v -X POST "$BASE/revoke" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$REFRESH_TOKEN"

# Expect: 200 OK

# Try to refresh with the revoked token
curl -v -X POST "$BASE/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN"

# Expect: 400 Bad Request (invalid_grant)
```

### 2. Revoke an access token

```
# Revoke the access token
curl -v -X POST "$BASE/revoke" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token_type_hint=access_token&token=$ACCESS_TOKEN"

# Expect: 200 OK

# Try to use it at userinfo
curl -v "$BASE/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN"

# Expect: 401 Unauthorized
```

### 3. Bad client auth produces an error

```
curl -v -X POST "$BASE/revoke" \
  -u "bad:credentials" \
  -d "token=$ANY_TOKEN"

# Expect: 401 Unauthorized
```

### 4. Garbage token returns 200 (silent failure)

```
curl -v -X POST "$BASE/revoke" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=not-a-valid-jwt"

# Expect: 200 OK
```

### 5. Revoke with `token_type_hint` mismatch

```
# Get an access token
# Revoke it but send token_type_hint=refresh_token
curl -v -X POST "$BASE/revoke" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token_type_hint=refresh_token&token=$ACCESS_TOKEN"

# Expect: 200 OK (falls through to access token handling)
```

### 6. Cross-client revocation rejected (silently)

```
# Get a token for client A
# Try to revoke it as client B
curl -v -X POST "$BASE/revoke" \
  -u "$CLIENT_B_ID:$CLIENT_B_SECRET" \
  -d "token=$TOKEN_FROM_CLIENT_A"

# Expect: 200 OK (but token remains valid — verify with userinfo)
```

### 7. Revoked token stays rejected after re-issuance

```
# Revoke an access token
# Get a new access token (same client, same user)
# The new token has a different jti — it should work
```

---

## References

- [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
