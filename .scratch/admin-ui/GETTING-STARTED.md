# Getting started — running the admin UI against a local backend

**Companion to [API-CONTRACT.md](API-CONTRACT.md)**. That file is the wire format. This one
is everything you need *before* you can call it: how to stand the backend up, how to log in,
and what to do when something 401s.

Everything here is dev-only. Nothing in this file is a production procedure.

---

## 1. Stand the backend up

From the `php-auth` repo:

```bash
composer install
mkdir -p db && touch db/data.db   # SQLite file, must exist before migrate
composer setup  # migrations + seed + RSA keys per realm
composer serve  # http://localhost:8000
```

Sanity check before touching the frontend:

```bash
curl -s http://localhost:8000/health          # {"status":"ok"}
curl -s http://localhost:8000/ready           # {"status":"ok"}  (touches the DB)
```

If `/health` is fine but `/ready` is `503`, the database is the problem, not the server.

---

## 2. What is already in the database

`composer setup` seeds everything the dashboard needs. You do not have to create it.

| Thing | Value |
|---|---|
| Admin realm name | `admin` |
| Admin realm id | `adc8cc40-943c-4fa4-97ed-2777baa49db5` |
| Admin login | `admin@example.com` / `ChangeMe!dev` |
| Admin role | `admin`, already assigned to that user |
| Dashboard client | `admin-ui`, public (`require_auth = 0`), PKCE, no secret |
| Dashboard redirect pattern | `http://localhost:5173/*` |
| Dashboard client scope | `openid profile email` |
| CI client | `ci-deployer`, confidential, has `offline_access` |
| Other realms | `web`, `test` |
| Dev API key | `dev-admin-token-change-me` (from `config.ini`) |

The seeded `admin-ui` URI pattern is `http://localhost:5173/*` **on purpose** — it is the
default Vite dev-server origin. If your dashboard runs on a different port or host, either run
it on 5173 or update the client's `uri` through the admin API (see §5).

---

## 3. Log in

Full flow, including why each step exists, is in
[API-CONTRACT.md §2](API-CONTRACT.md#2-logging-in-oidc-authorization-code--pkce). The short
version:

1. The SPA generates `state`, `nonce`, and a PKCE `code_verifier`, stores them in
   `sessionStorage`, and redirects the browser to:

   ```
   http://localhost:8000/realms/admin/protocol/openid-connect/auth
     ?client_id=admin-ui
     &response_type=code
     &scope=openid profile email
     &redirect_uri=http://localhost:5173/auth/callback
     &state=<random>
     &nonce=<random>
     &code_challenge=<S256 base64url of the verifier>
     &code_challenge_method=S256
   ```

2. **The backend serves the login page.** The human types `admin@example.com` /
   `ChangeMe!dev`. Do not try to build this form in the SPA.

3. The backend redirects to `http://localhost:5173/auth/callback?code=...&state=...`.

4. The SPA checks `state`, then:

   ```
   POST http://localhost:8000/realms/admin/protocol/openid-connect/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=<code>
   &redirect_uri=http://localhost:5173/auth/callback
   &client_id=admin-ui
   &code_verifier=<the original verifier>
   ```

   The response is form-encoded, not JSON: `access_token=...&token_type=Bearer&expires_in=300&refresh_token=...&refresh_expires_in=1800&scope=openid%20profile%20email`. Parse it with `URLSearchParams`, **not** `res.json()`.

5. Keep **both** `access_token` and `refresh_token`, in memory only — not `localStorage`.

6. Send `Authorization: Bearer <access_token>` on every `/admin/*` call.

The access token expires in **300 seconds**. It comes with a refresh token that needs no
`offline_access` scope, so the normal path is to refresh rather than bounce the operator back
to the login screen:

```
POST http://localhost:8000/realms/admin/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh>&client_id=admin-ui
```

`refresh_expires_in` is 1800 seconds. Do **not** add `offline_access` to the `admin-ui`
client — an offline token is a 30-day standing credential, which is not what a dashboard
should hold in a browser.

---

## 4. Verify a token before you build UI on it

Fastest way to know the login path is correct, without any frontend code:

```bash
# 1. get a token (form-encoded response, so parse it as a query string)
curl -s -X POST http://localhost:8000/realms/admin/protocol/openid-connect/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=ci-deployer' \
  -d 'client_secret=ci-deployer-dev-secret' | tr '&' '\n' | grep access_token
```

That is the CI path, not the browser path, but it proves the realm and keys work. To confirm
the **admin role** claim, call any admin endpoint with the token — a `200` on
`GET /admin/realms` means the token carries the `admin` role and the middleware accepted it.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/admin/realms
```

If that returns `401`, the token is valid but the role check failed, or the token is for a
different realm. Decode it locally against the JWKS to see `realm_access`:

```bash
curl -s http://localhost:8000/realms/admin/protocol/openid-connect/certs
```

---

## 5. The static API key (dev only)

Works as `Authorization: Bearer dev-admin-token-change-me`. Two warnings:

- **The dashboard does not use this.** Authenticate with a JWT from the admin realm. The
  static key is a CLI/curl convenience: put it in the `Authorization` header, because
  `X-Admin-Key` is not in the CORS allowed-headers list and would fail preflight from a browser.
- **It is going away eventually, but there is no deadline to track** — that work (F-49) is
  blocked until this dashboard is deployed, because the static key is currently the only way to
  create realms and clients in a live environment. Do not build the dashboard on it anyway: it
  exists so the realm and clients can be bootstrapped before you arrive.

Useful for bootstrapping without a browser, e.g. adding a redirect URI for a dashboard running
on a different port:

```bash
curl -s -X PUT http://localhost:8000/admin/clients/8d8dbe43-1257-4f00-9ef0-0d3d15a34207 \
  -H "Authorization: Bearer dev-admin-token-change-me" \
  -H "Content-Type: application/json" \
  -d '{"uri":"http://localhost:4173/*"}'
```

The `admin-ui` client id is in the table in §2.

---

## 6. Cross-origin setup

`config.ini` ships with `allowed_origins = *`, which reflects any origin, so a dashboard on
`localhost:5173` works with no configuration. **Pin it before deploying anywhere shared:**

```ini
[server]
allowed_origins = http://localhost:5173,https://admin.example.com
```

An empty or absent list emits no CORS headers at all, and the browser blocks every read.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401` with `WWW-Authenticate: ... realm="admin"` on every admin call | token is fine but has no `admin` role, or is from another realm | decode it; you need `realm_access.roles` to contain `admin` |
| CORS error in the console, no request visible | origin not allowed | check `allowed_origins`; remember an empty list denies everything |
| Preflight fails | a header outside the allowed list | only `content-type, accept, origin, authorization` are allowed — notably **not** `X-Admin-Key` |
| Token request returns 400 and a query string, not JSON | `/token` is form-encoded | parse with `URLSearchParams` |
| Token works, then 401s a minute later | `access_token_expires_in` is 300s | expected; refresh or re-login on 401 |
| Login page loops back to itself | `redirect_uri` does not match the client `uri` | the `uri` pattern must match the full callback URL |
| Login page shows after a valid session | `prompt=login` was sent | do not send `prompt` |
| `404` on an admin route | a missing `base_path` prefix | `config.ini` `base_path` must match how the app is mounted |
| `409` on a delete | something is still referencing it | see the guard table in [DOMAIN-MODEL.md §4](DOMAIN-MODEL.md#4-what-blocks-a-delete) |
| Realm list has no `total` field | realms are not paginated yet | expected, tracked as F-52; see API-CONTRACT §5.1 |
| `db/data.db` missing | file was never created | `touch db/data.db`, then `composer migrate` |

---

## 8. What not to do

- **Do not put the access token in `localStorage`.** It is a full admin credential; a page
  reload is a far smaller problem than an XSS becoming a realm compromise.
- **Do not send passwords anywhere but over TLS.** The admin API takes user passwords as
  plaintext and hashes them server-side, so the request itself is the sensitive part.
- **Do not build the login form in the SPA.** See §3.
- **Do not link `/admin/db` from the dashboard.** It is a database admin tool, not an app
  feature.
