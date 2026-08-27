# php-auth

An OpenID Connect-like PHP authorization server implementing the authorization code
grant flow with PKCE, token refresh, revocation, introspection, and offline access.

Designed to be compatible with a subset of Keycloak **≥20** functionality — the
[Keycloak JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter)
is used in the frontend to test and verify the server's OIDC behaviour.

[![Deploy](https://github.com/Em-Ant/php-auth/actions/workflows/deploy.yml/badge.svg)](https://github.com/Em-Ant/php-auth/actions/workflows/deploy.yml)

---

## Requirements

- PHP **8.3+** (8.1 minimum, 8.3+ recommended)
- SQLite 3
- OpenSSL (for RSA key pair generation)
- [Composer](https://getcomposer.org/)

---

## Quick start

```bash
# 1. Create the SQLite database file
touch db/data.db

# 2. Install PHP dependencies
composer install

# 3. Run migrations and seed dev data (realms, users, clients)
composer setup

# 4. Generate RSA key pairs for token signing
#    (run once; keys go into keys/<kid>/)
php -r 'require "vendor/autoload.php"; \AuthServer\Services\TokenService::createKeys();'

# 5. Start the dev server
composer serve
```

The dev server runs at `http://localhost:8000`.

Open the [Keycloak test app](https://www.keycloak.org/app/?url=http://localhost:8000&realm=test&client=kc_app)
or configure any OIDC client with:

| Setting | Value |
|---|---|
| Issuer | `http://localhost:8000/realms/test` |
| Authorization endpoint | `http://localhost:8000/realms/test/protocol/openid-connect/auth` |
| Token endpoint | `http://localhost:8000/realms/test/protocol/openid-connect/token` |

---

## Seed data

`composer setup` seeds two realms with test data:

| Realm | Client | User (email / password) |
|---|---|---|
| `test` | `local` (redirect: `http://localhost:5173`) | `test@example.com` / `tst` |
| `test` | `kc_app` (redirect: `https://www.keycloak.org/app`) | `test@example.com` / `tst` |
| `web` | `playground` | `test@example.com` / `tst` |

Clients have `require_auth = false` in seed data (no client secret needed for
the token endpoint).

---

## OIDC endpoints

All endpoints live under `/realms/{realm}/protocol/openid-connect/`.

| Endpoint | Method | Description |
|---|---|---|
| `/auth` | `GET` | Authorization request — renders login form |
| `/login-actions/authenticate` | `POST` | Authenticate user with email + password |
| `/token` | `POST` | Exchange code for tokens, or refresh tokens |
| `/token/introspect` | `POST` | Introspect token validity (RFC 7662) |
| `/revoke` | `POST` | Revoke access or refresh token (RFC 7009) |
| `/userinfo` | `GET` | Returns user profile claims (requires Bearer token) |
| `/certs` | `GET` | JWKS public keys for token signature verification |
| `/logout` | `GET` | End session (requires `id_token_hint`) |
| `/login-status-iframe.html` | `GET` | Third-party cookie detection iframe |

### Discovery

```
GET /realms/{realm}/.well-known/openid-configuration
```

Returns the OpenID Connect Discovery document describing all supported endpoints,
grant types, signing algorithms, and scopes.

### Authentication flow

```
GET  /realms/{realm}/protocol/openid-connect/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...&nonce=...
POST /realms/{realm}/protocol/openid-connect/login-actions/authenticate?q={login_id}
POST /realms/{realm}/protocol/openid-connect/token
```

The server renders a login form, validates credentials, issues an authorization
code, and on exchanging the code returns a token bundle with `access_token`,
`refresh_token`, `id_token`, and `expires_in`.

### Token introspection

```
POST /realms/{realm}/protocol/openid-connect/token/introspect
Content-Type: application/x-www-form-urlencoded

token=<token>&client_id=<client_id>
```

Returns `200 OK` with `{"active": true/false}`. Active tokens include the full
set of claims (`sub`, `aud`, `iss`, `exp`, `iat`, `jti`, `token_type`,
`client_id`, `scope`, `sid`).

Supports both access tokens (RS256 signature verification + blacklist check) and
refresh tokens (database lookup of `logins.refresh_token`).

### Token revocation

```
POST /realms/{realm}/protocol/openid-connect/revoke
Content-Type: application/x-www-form-urlencoded

token=<token>&client_id=<client_id>&token_type_hint=access_token
```

Accepts `access_token` (blacklists the JTI) or `refresh_token` (expires the
underlying login row). Omitting `token_type_hint` defaults to refresh token
handling.

### Token refresh

```
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=<client_id>&refresh_token=<token>
```

Returns a new token bundle with rotated refresh token.

### Offline access

Offline access lets a client obtain refresh tokens that stay valid after the
user's SSO session ends. Ask for it by including `offline_access` in the
`scope` of the authorization request:

```
GET /realms/{realm}/protocol/openid-connect/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid offline_access&state=...&nonce=...
```

At the token endpoint the server responds with a bundle whose refresh token
carries `typ: Offline` and a `refresh_expires_in` (default 2592000 s = 30 days):

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "...",
  "expires_in": 300,
  "refresh_expires_in": 2592000,
  "token_type": "Bearer",
  "scope": "openid offline_access"
}
```

Offline refresh tokens:

- **Survive logout** — they are not touched by `/logout` or expired SSO
  sessions. A user can sign out of the browser and the client can still
  refresh tokens in the background (Keycloak-compatible behaviour).
- **Rotate on every refresh**, like regular refresh tokens, and have a sliding
  lifetime: each refresh resets `updated_at`, so the token stays valid while it
  is being used.
- **Are bound to the issuing client** — refreshing with a different
  `client_id` is rejected, and the granted scope can never be widened.
- **Can be revoked** via RFC 7009 (`POST /revoke` with `token_type_hint=refresh_token`),
  or introspected via `POST /token/introspect`.
- **Per-realm lifetime** — `offline_refresh_token_expires_in` on the realm
  controls the sliding TTL (default 2592000 s; configurable via the admin API).

An offline grant is a persistent server-side record (`offline_sessions`) that
is independent of the SSO session — that is what lets it outlive logout. For
admin-initiated revocation without the token, see
[Admin API — Sessions](#admin-api--sessions).

### Scope-role mapping (F-05)

Clients can control which roles appear in tokens by mapping scopes to roles.
This follows Keycloak-style hybrid semantics:

**Full-scope fallback (no mappings):** When a client has no scope-role
mappings, all realm and client roles the user holds are emitted in the token.
This is the default behaviour and maintains backward compatibility.

**Mapped-only (any mappings exist):** When a client has one or more scope-role
mappings, only roles explicitly mapped to the requested scopes are emitted.
Additionally, if a scope has a `required` mapping and the user lacks that
role, the entire scope is dropped from the grant.

Example scenario:

| Scope | Role | Required | User holds role | Result |
|---|---|---|---|---|
| `openid` | `admin` | no | yes | Role `admin` included in `realm_access.roles`; scope kept |
| `profile` | `basic` | no | yes | Role `basic` included in `realm_access.roles`; scope kept |
| `email` | `admin` | **yes** | **no** | Scope `email` **dropped** from grant |

The `resource_access.<client>.roles` claim only emits client roles whose
namespace matches the requesting client, matching full-scope behaviour.

Scope-role mappings are stored in the `client_scope_roles` table and managed
via the admin API (see [Admin API — Scope-role mappings](#scope-role-mappings)).

---

## Tokens

All tokens are RS256-signed JWTs with the following claims:

| Claim | Description |
|---|---|
| `jti` | Unique token identifier |
| `iss` | Issuer URL (`<issuer>/realms/<realm>`) |
| `aud` | Client name (for access/ID) or issuer (for refresh) |
| `sub` | User ID |
| `typ` | Token type: `Bearer`, `Refresh`, `Offline`, or `ID` |
| `sid` | Session ID |
| `exp` / `iat` | Expiration and issued-at timestamps |
| `scope` | Granted scopes |

Access token expiry is configurable per realm in `config.ini`
(`access_token_expires_in`, default 300 s). Refresh tokens use
`refresh_token_expires_in` (default 1800 s).

---

## Configuration

Copy `config.ini` (created on setup) and edit:

```ini
[server]
issuer = http://localhost:8000
base_path = /

[password_hashing]
algorithm = argon2id

[log]
print = true
write = false

[rate_limiting]
authenticate_limit = 10
authenticate_window = 60
token_limit = 30
token_window = 60

[admin]
api_key = dev-admin-token-change-me
```

---

## Admin API

The admin API manages realms, clients, users, signing keys, sessions, logins,
and migrations over HTTP. It is **not** part of the OIDC surface — every
endpoint below lives under `/admin` and requires the admin API key.

### Authentication

Set `admin.api_key` in `config.ini` (default `dev-admin-token-change-me`).
Send it either as a Bearer token or via the `X-Admin-Key` header:

```
Authorization: Bearer <admin_api_key>
# or
X-Admin-Key: <admin_api_key>
```

Invalid or missing keys get `401` with `{"error": "unauthorized", "message": "invalid or missing admin token"}`.
Request and response bodies are JSON (`Content-Type: application/json`).
Validation errors return `400`, duplicate/guarded operations return `409`,
missing resources return `404`, success without a body returns `204`.

### Signing keys

| Endpoint | Method | Description |
|---|---|---|
| `/admin/keys` | `POST` | Generate a new RSA key pair |

```
POST /admin/keys
→ 201 {"kid": "<kid>"}
```

Keys are written to `keys/<kid>/`. New realms reference a `keys_id` (the KID);
realms without an explicit key share the first available key set.

### Realms

| Endpoint | Method | Description |
|---|---|---|
| `/admin/realms` | `GET` | List realms |
| `/admin/realms` | `POST` | Create a realm |
| `/admin/realms/{id}` | `GET` | Read a realm |
| `/admin/realms/{id}` | `PUT` | Update a realm |
| `/admin/realms/{id}` | `DELETE` | Delete a realm (only when it has no clients or users) |

Create body:

```json
{
  "name": "myrealm",
  "keys_id": "<kid>",
  "refresh_token_expires_in": 1800,
  "access_token_expires_in": 300,
  "pending_login_expires_in": 1800,
  "authenticated_login_expires_in": 1800,
  "session_expires_in": 86400,
  "idle_session_expires_in": 1800,
  "scope": "openid profile email",
  "offline_refresh_token_expires_in": 2592000
}
```

All numeric TTL fields and `scope` are optional (sensible defaults apply).
`PUT` accepts the same fields as a partial update. Realm responses include the
full set of TTLs plus `offline_refresh_token_expires_in` (sliding lifetime of
offline refresh tokens, default 2592000 s).

### Clients

| Endpoint | Method | Description |
|---|---|---|
| `/admin/clients` | `GET` | List clients (`?realm_id=`) |
| `/admin/clients` | `POST` | Create a client |
| `/admin/clients/{id}` | `GET` | Read a client |
| `/admin/clients/{id}` | `PUT` | Update a client |
| `/admin/clients/{id}` | `DELETE` | Delete a client (409 while it has active logins or offline sessions) |

Create body:

```json
{
  "name": "myapp",
  "realm_id": "<realm-id>",
  "uri": "https://app.example.com/callback",
  "require_auth": false,
  "scope": "openid profile email",
  "client_secret": "optional-secret"
}
```

`client_secret` is stored hashed; responses only report `has_secret: true/false`.
`require_auth` toggles whether the token endpoint demands client authentication.

### Users

| Endpoint | Method | Description |
|---|---|---|
| `/admin/users` | `GET` | List users (`?realm_id=`) |
| `/admin/users` | `POST` | Create a user |
| `/admin/users/{id}` | `GET` | Read a user |
| `/admin/users/{id}` | `PUT` | Update a user |
| `/admin/users/{id}` | `DELETE` | Delete a user (409 while it has active sessions or offline sessions) |

Create body:

```json
{
  "realm_id": "<realm-id>",
  "email": "user@example.com",
  "password": "secret",
  "name": "Optional name",
  "realm_roles": "basic",
  "valid": true
}
```

Passwords are hashed (argon2id) and never returned. `PUT` accepts the same
fields as a partial update; omit `password` to keep the existing one.

### Roles

| Endpoint | Method | Description |
|---|---|---|
| `/admin/roles` | `GET` | List roles (`?realm_id=`, `?client_id=`) |
| `/admin/roles` | `POST` | Create a role |
| `/admin/roles/{id}` | `GET` | Read a role |
| `/admin/roles/{id}` | `PUT` | Update a role |
| `/admin/roles/{id}` | `DELETE` | Delete a role (409 while assigned to users) |

Create body:

```json
{
  "name": "editor",
  "realm_id": "<realm-id>",
  "client_id": null,
  "description": "Can edit content"
}
```

`client_id` is optional — omit or set to `null` for realm roles; set to a
client ID for client roles. Role names must be unique within their realm (for
realm roles) or client (for client roles).

### User role assignments

| Endpoint | Method | Description |
|---|---|---|
| `/admin/users/{id}/roles` | `GET` | List roles assigned to a user |
| `/admin/users/{id}/roles` | `POST` | Assign a role to a user |
| `/admin/users/{id}/roles/{role_id}` | `DELETE` | Unassign a role from a user |

Assign body:

```json
{
  "role_id": "<role-id>"
}
```

### Scope-role mappings

| Endpoint | Method | Description |
|---|---|---|
| `/admin/clients/{id}/scope-roles` | `GET` | List scope-role mappings for a client |
| `/admin/clients/{id}/scope-roles` | `POST` | Create a scope-role mapping |
| `/admin/clients/{id}/scope-roles/{scope}/{role_id}` | `PUT` | Update a mapping (change `required`) |
| `/admin/clients/{id}/scope-roles/{scope}/{role_id}` | `DELETE` | Delete a mapping |

Create body:

```json
{
  "scope": "profile",
  "role_id": "<role-id>",
  "required": false
}
```

When a client has scope-role mappings, only roles explicitly mapped to the
requested scopes are emitted in tokens. A `required` mapping drops the entire
scope from the grant when the user lacks the role. See
[Scope-role mapping](#scope-role-mapping-f-05) for details.

### Sessions

| Endpoint | Method | Description |
|---|---|---|
| `/admin/sessions` | `GET` | List sessions (`?realm_id=`, `?user_id=`) |
| `/admin/sessions/{id}` | `DELETE` | Delete a session and its logins |
| `/admin/sessions/invalidate` | `POST` | Invalidate all sessions and offline grants for a user and/or client |

Invalidate body — at least one of `user_id` / `client_id` is required:

```json
{
  "user_id": "<user-id>",
  "client_id": "<client-id>"
}
```

```
→ 200 {"invalidated": 3}
```

Deleting a session or invalidating a user/client also **expires their offline
refresh grants** (`offline_sessions`) — this is the admin-side revocation path
for offline access, since offline tokens deliberately survive SSO logout and
are otherwise only revocable with the token itself (RFC 7009).

### Logins

| Endpoint | Method | Description |
|---|---|---|
| `/admin/logins` | `GET` | List logins (`?realm_id=`, `?client_id=`) |
| `/admin/logins/{id}` | `DELETE` | Delete a login (expires its refresh token) |

### Migrations

| Endpoint | Method | Description |
|---|---|---|
| `/admin/migrations/migrate` | `POST` | Apply pending migrations |
| `/admin/migrations/rollback` | `POST` | Roll back (`?steps=N`, default 1) |
| `/admin/migrations/go` | `POST` | Migrate to a specific `?version=` |
| `/admin/migrations/status` | `GET` | List applied/pending migrations |
| `/admin/migrations/dry-run` | `GET` | List pending migrations without applying |

### Database browser

The bundled [Adminer](https://www.adminer.org/) UI is served at `/admin/db`
(any path under it). It is protected by the same admin API key.

---

## Testing

```bash
composer test           # PHPUnit — unit + integration (in-memory SQLite)
composer test:e2e       # E2E smoke test against running dev server (bash + curl)
composer stan           # PHPStan (level 5)
composer cs_check       # PHPCS (PSR-12)
composer check          # stan + cs_check — run before committing
```

---

## Deployment

php-auth is supported on **HTTPS-only** deployments. TLS is a hard dependency,
not a recommendation:

- **`AUTH_SESSION` / `AUTH_SESSION_CHECK` cookies are always sent with
  `Secure` and `SameSite=None`** (see `HttpSessionCookieHandler`), so the
  server-side cookie never works over plain HTTP in a real browser.
- **The 3rd-party cookie check-session iframe
  (`login-status-iframe.html`) uses the Web Crypto API
  (`crypto.subtle.digest`) to verify the session state.** `crypto.subtle` is
  only available in a **secure context** (HTTPS, or a `localhost` exception).
  Over plain HTTP the digest promise rejects and session monitoring silently
  stops working, so HTTP is not supported.
- Serving behind a reverse proxy is fine — set `issuer`/`base_path` in
  `config.ini` accordingly — but the proxy must terminate TLS and forward the
  request as `https`.

Local development on `http://localhost:8000` still works (the `localhost`
secure-context exception covers the iframe, and the dev server is not
user-facing).

See **[ADR-0003](docs/adr/0003-https-only-deployments.md)** for the full
decision and reasoning.

---

## Development commands

| Command | Action |
|---|---|
| `composer serve` | Dev server at `localhost:8000` |
| `composer migrate` | Run pending migrations |
| `composer seed` | Re-seed dev data (idempotent) |
| `composer setup` | Migrate + seed in one step |
| `composer dump-autoload` | Refresh autoloader after adding classes |

---

## Architecture

- **Single entrypoint**: `public/index.php` loads the DI container, wires all
  routes and middleware inline.
- **DI container**: PHP-DI with autowiring. Definitions in `src/Config/Definitions.php`.
- **No framework magic**: Slim 4 with PSR-7/PSR-15 middleware.
- **SQLite backend**: Repositories take `\PDO` directly. In-memory SQLite for tests.
- **Versioned migrations**: Plain SQL files in `migrations/` (`.up.sql` / `.down.sql`).
- **RSA key pairs**: Stored in `keys/<kid>/` with `public_key.pem`,
  `private_key.pem`, `cert.pem`, and `keys.json` (JWKS format).

---

## License

MIT