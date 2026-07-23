# Introspection Endpoint (RFC 7662)

Add `POST /realms/{realm}/protocol/openid-connect/token/introspect` so resource
servers can query token validity and metadata.

---

## No new tables — reads from existing `logins` and `token_blacklist`.

---

## Endpoint: `POST /token/introspect`

### Request

| Field | Required | Description |
|---|---|---|
| `token` | yes | The token string to introspect |
| `token_type_hint` | no | `access_token` or `refresh_token` |

Client authentication is the same as the token endpoint. RFC 7662 Section 2 says
the endpoint is protected — only authenticated clients can call it.

### Response

**`200 OK`** always. The body is a JSON object with an `active` boolean.

If **`active: true`**, also include token claims as top-level keys:

```json
{
  "active": true,
  "sub": "user-1",
  "aud": "web-client",
  "iss": "http://localhost:8000/realms/web",
  "exp": 1712345678,
  "iat": 1712345378,
  "jti": "abc123",
  "token_type": "Bearer",
  "client_id": "web-client",
  "scope": "openid profile",
  "sid": "session-xyz"
}
```

If **`active: false`**, return only `{"active": false}`.

### Behaviour

1. Validate client credentials (same as `POST /token`).
2. Try to decode the token to extract `jti`, `exp`, `aud`, `iss`, and
   `token_type` (the JWT `typ` header).
3. Determine token category:
   - `typ: "Refresh"` → handle as refresh token.
   - Otherwise (`typ: "Bearer"`, `typ: "ID"`, or absent) → handle as access token.
4. **Refresh token path**: look up `logins.refresh_token` by exact string match.
   This is the same validation the token endpoint uses — the DB row is the
   source of truth, not the JWT signature. If found (row status is `ACTIVE`
   and the token's `exp` claim hasn't passed) → `active: true`. Return
   claims from the token payload plus `token_type: "refresh_token"`.
5. **Access token path**: verify RS256 signature via `TokenService::validateToken()`,
   check `exp`, check `token_blacklist` for the `jti`. All pass → `active: true`.
   Return the token payload claims.
6. If anything fails → `active: false`.

### Error cases

| Situation | Response |
|---|---|
| Client auth fails | `401 Unauthorized` |
| Token missing | `400 Bad Request` |
| Malformed token / sig fails | `200 OK` with `{"active": false}` |

---

## Well-known config

Update `OidcController::sendConfig`:

```php
'introspection_endpoint' => $issuer . '/protocol/openid-connect/token/introspect',
'introspection_endpoint_auth_methods_supported' => ['client_secret_basic'],
```

---

## Verification checklist

### 1. Introspect an active access token

```
# Get tokens via full OIDC flow

curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"

# Expect: 200 OK
# Response has "active": true + all claims
```

### 2. Introspect an active refresh token

```
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$REFRESH_TOKEN"

# Expect: 200 OK with "active": true
# token_type should be "refresh_token"
```

### 3. Introspect a revoked token

```
# Revoke the access token first (issue #01)
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"

# Expect: 200 OK with "active": false
```

### 4. Introspect an expired token

```
# Manually modify the exp claim or wait — easier: craft a token with
# exp in the past using the same kid, or just decode an existing token
# and modify exp, then re-sign (but you'd need the private key).

# Simpler: use a token from another realm's kid that won't validate.
```

### 5. Introspect with bad client credentials

```
curl -v -X POST "$BASE/token/introspect" \
  -u "bad:creds" \
  -d "token=$ACCESS_TOKEN"

# Expect: 401 Unauthorized
```

### 6. Introspect a garbage string

```
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=not-a-jwt"

# Expect: 200 OK with "active": false
```

### 7. Cross-client introspection

```
# Get a token for client A
# Introspect it as client B (but it's a valid token from a different client)
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_B_ID:$CLIENT_B_SECRET" \
  -d "token=$TOKEN_FROM_CLIENT_A"

# Expect: 200 OK with "active": true
# The aud/client_id claim will show it belongs to client A, but it's still active
# (RFC 7662 doesn't restrict which client can introspect — any authenticated
#  client can introspect any token)
```

### 8. Introspect an ID token

```
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ID_TOKEN"

# Expect: 200 OK with "active": true (or false if expired)
# Includes sub, iss, aud, exp, etc.
```

### 9. `token_type_hint` mismatch

```
# Send access token with token_type_hint=refresh_token
curl -v -X POST "$BASE/token/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token_type_hint=refresh_token&token=$ACCESS_TOKEN"

# Expect: 200 OK — server ignores hint if it doesn't match, falls through
# This is allowed per RFC 7662 Section 2
```

---

## References

- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
