# php-auth

An OpenID Connect-like PHP authorization server implementing the authorization code
grant flow with PKCE, token refresh, revocation, and introspection.

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

---

## Tokens

All tokens are RS256-signed JWTs with the following claims:

| Claim | Description |
|---|---|
| `jti` | Unique token identifier |
| `iss` | Issuer URL (`<issuer>/realms/<realm>`) |
| `aud` | Client name (for access/ID) or issuer (for refresh) |
| `sub` | User ID |
| `typ` | Token type: `Bearer`, `Refresh`, or `ID` |
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
```

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