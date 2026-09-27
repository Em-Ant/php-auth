# Admin API contract — handoff for the Admin UI SPA

**Status**: as implemented on the backend at commit `006ff4b`. Every field below was read out
of the controller source, not out of a design doc.

**Audience**: whoever builds the React + Vite + shadcn admin dashboard in the separate repo.
This file is the single source of truth for the wire format. If the frontend needs a field
that is not listed here, it does not exist yet — ask, do not guess.

**Start with [README.md](README.md)** in this folder. For setup and credentials see
[GETTING-STARTED.md](GETTING-STARTED.md); for entity semantics, the delete-guard rules, and
the exact enum values see [DOMAIN-MODEL.md](DOMAIN-MODEL.md).

**Backend repo**: `php-auth`. **Backend base URL** (dev): `http://localhost:8000`.
**Frontend dev origin**: `http://localhost:5173` (already seeded as the `admin-ui` client URI).

---

## 1. Authentication

**Every `/admin/*` endpoint below requires the `Authorization: Bearer <token>` header. This is
stated once here and omitted from each endpoint listing.**

Two token kinds are accepted:

| Token kind | How to get it | When to use it |
|---|---|---|
| **Admin JWT** (recommended) | OIDC authorization-code + PKCE login against the `admin` realm, see §2 | The dashboard, always |
| **Static API key** | `[admin] api_key` from `config.ini` | Local dev bootstrap only |

The middleware accepts the bearer JWT only if its `realm_access.roles` claim contains
`admin`. The static key is accepted as `Authorization: Bearer <api_key>` and is currently
still allowed on every `/admin/*` path (dual-mode, `allow_all = true`). **Do not build the
dashboard around the static key** — a scheduled ticket narrows it to the ops endpoints only.

> **CORS.** The allowed request headers are `content-type, accept, origin, authorization` —
> `Authorization` is on the list, so the dashboard's JWT calls preflight cleanly. `X-Admin-Key`
> is not, so a browser must never send that header; use the `Authorization` header for the
> static key instead. The dashboard has no reason to send `X-Admin-Key` at all, since it
> authenticates with a JWT.

### Failures

- `401` with `WWW-Authenticate: Bearer realm="admin", error="invalid_token", ...` when the
  token is missing, invalid, or lacks the admin role.
- `500` with `error: "server_error"` on a database failure. Never a `400`.

---

## 2. Logging in (OIDC authorization code + PKCE)

The `admin` realm is a normal realm, so the dashboard logs in through the standard flow. A
public client named `admin-ui` is already seeded with `require_auth = 0` and URI
`http://localhost:5173/*`, scope `openid profile email` (deliberately **no** `offline_access`,
so the browser session is not a long-lived credential).

### Do not implement the login form in the SPA

The backend **serves the login page itself**. The SPA must **redirect** the browser to the
authorize endpoint and only handle the callback. Do not fetch `/auth` and post to
`/login-actions/authenticate` from JavaScript — that endpoint expects a CSRF token and a
login id that are issued inside a server-rendered HTML form, and it sets an `HttpOnly`
session cookie the browser has to carry. It is not a JSON API.

What the SPA actually does:

| Step | Who | What |
|---|---|---|
| 1 | SPA | Generate `state`, `nonce`, a PKCE `code_verifier`, and its `code_challenge`. Save all three in `sessionStorage`. Full-page redirect to `/auth?...`. |
| 2 | Backend | Serves the HTML login form. **The human types email and password here.** Sets an `HttpOnly` `AUTH_SESSION` cookie. |
| 3 | Backend | Redirects to the SPA callback with `?code=...&state=...`. |
| 4 | SPA | Verify `state` matches. POST to `/token` with `code` + `code_verifier`. |
| 5 | SPA | Keep the `access_token` **and** the `refresh_token` from the response. Call the admin API with the access token. |

The SPA needs a **callback route** on its own origin (for example `/auth/callback`) and that
exact URL registered as the `redirect_uri`. The seeded client allows the `http://localhost:5173/*`
pattern, so any path under that host matches.

**Step 5 detail — the token response, and where it goes.** The authorization-code response
carries a **refresh token already**, and it is not an offline token:

```
access_token=...&token_type=Bearer&expires_in=300
&refresh_token=...&refresh_expires_in=1800
&id_token=...&scope=openid profile email&session_state=...
```

That `refresh_token` is issued unconditionally by this grant and is governed by
`refresh_expires_in` (1800s) on the realm. It needs **no** `offline_access` scope and no
change to the `admin-ui` client. Use it: when the 300s access token expires, POST
`grant_type=refresh_token` to `/token` to get a new one. That is what keeps the dashboard from
bouncing the operator to the login screen every five minutes.

**Do not add `offline_access` to `admin-ui`.** It is excluded on purpose — an offline token is
a 30-day standing credential, and a browser-reachable long-lived admin token is not a trade
worth making for a dashboard.

**Where the tokens live: memory only.** Neither the access token nor the refresh token belongs
in `localStorage` or a cookie readable by script. Both are full admin credentials, so any XSS
in the dashboard becomes a full realm compromise. The cost is that a page reload loses the
session and the app needs a silent re-auth on boot — a silent redirect that the still-live SSO
session satisfies without a password prompt. That is the right trade for an admin tool; make
it consciously rather than by default.

`state` and `nonce` must be verified on the callback. A callback that arrives with no
matching `state` in `sessionStorage` is a CSRF attempt, not a login.

### Reference: the raw HTTP sequence

Only needed for non-browser clients or for debugging with curl. In a browser, skip it.

| Step | Request |
|---|---|
| 1. Authorize | `GET /realms/admin/protocol/openid-connect/auth?client_id=admin-ui&response_type=code&scope=openid%20profile%20email&redirect_uri=<registered>&state=<random>&nonce=<random>&code_challenge=<S256 of verifier>&code_challenge_method=S256` |
| 2. User authenticates | `POST /realms/admin/protocol/openid-connect/login-actions/authenticate?q={login_id}`, form-encoded `emailemail`, `password`, `csrf_token` — all from`csrf_token` — all from the HTMLHTML formform servedserved inin step 1, with that step's cookies, with that step's cookies |
| 3. Exchange code | `POST /realms/admin/protocol/openid-connect/token`, form-encoded `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id=admin-ui`, `code_verifier` |
| 4. Call admin API | `Authorization: Bearer <access_token>` |

PKCE is fully implemented: `code_challenge` / `code_challenge_method` on the authorize
request, `code_verifier` checked at the token endpoint, and the challenge is persisted on the
login row. `bin/e2e-test.sh` contains a working scripted version of the whole flow if you
need a reference implementation.

**The access token is the admin credential** — its `realm_access.roles` contains `admin`.

Also useful, no auth needed: `GET /realms/admin/.well-known/openid-configuration` and
`GET /realms/admin/protocol/openid-connect/certs` (the JWKS, for decoding the token locally
sothe token locally
so you cancan read the admin rolethe admin role client-side instead of calling the API to find out who you

are).

---

## 3. Shared conventions

### Headers

**Request**

| Header | Required | Notes |
|---|---|---|
| `Authorization: Bearer <token>` | yes, on all `/admin/*` | see §1 |
| `Content-Type: application/json` | yes on POST/PUT with a body | `application/x-www-form-urlencoded` is also parsed, but send JSON |
| `Origin` | automatic | must be in `[server] allowed_origins`, currently `*` |

**Response** (every JSON response carries these)

`Content-Type: application/json`, `Cache-Control: no-store`, `Pragma: no-cache`.

### Error envelope

Every failure uses the same OAuth2-shaped body:

```json
{ "error": "invalid_request", "error_description": "missing required field 'email'" }
```

`error` is a stable slug; `error_description` is a human sentence and **must not be parsed
for logic** — only displayed. Slugs you will see:

| HTTP | `error` | Cause |
|---|---|---|
| 400 | `invalid_request` | missing field, bad type, bad value, unknown realm/role reference |
| 401 | `unauthorized` | missing or invalid admin token |
| 404 | `not found` | no such id |
| 409 | `conflict` | duplicate name+uri, guarded delete blocked, public/confidential secret violation |
| 500 | `server_error` | database or storage failure |
| 500 | `migration_failed` | migration endpoint only |

### List envelope

All list endpoints except `GET /admin/realms` (§5.1) return:

```json
{ "items": [ ... ], "total": 42, "limit": 50, "offset": 0 }
```

`total` is the **unfiltered-by-pagination** match count, so it drives the pager directly.

**Pagination rules** — query params `limit` and `offset`, on every list endpoint:

- `limit` default `50`, valid range `1`–`200`.
- `offset` default `0`, no upper bound.
- An out-of-range or unparseable value is **silently replaced by the default** — it is not
  clamped and not an error. `limit=500` yields `limit=50`. `limit=0` yields `limit=50`.
  **The UI must send values it knows are valid, and must read `limit` back out of the
  response** rather than assuming what it asked for.

### Filters

Beyond `limit`/`offset`, these query params are supported per endpoint. They combine with AND.

| Endpoint | Filters |
|---|---|
| `/admin/users` | `realm_id` |
| `/admin/clients` | `realm_id` |
| `/admin/sessions` | `realm_id`, `user_id` |
| `/admin/logins` | `realm_id`, `client_id` |
| `/admin/offline-sessions` | `realm_id`, `user_id`, `client_id` |
| `/admin/roles` | `realm_id`, `client_id` |
| `/admin/audit-logs` | `action`, `actor_type`, `target_type`, `realm_id`, `from`, `to` |
| `/admin/users/{id}/roles` | pagination only |
| `/admin/clients/{id}/scope-roles` | pagination only |
| `/admin/realms` | none, and not paginated — see §5.1 |

> **Known gap: there is no free-text search.** You cannot look a user up by email or a client
> by name through the API. Filter by `realm_id` and page. A `?q=` / `?email=` search param is
> queued as a small additive change; if your table needs it, ask for it to be prioritised
> rather than building client-side search over paginated pages.

### Value formats

- `created_at` / `updated_at` / `authenticated_at`: `YYYY-MM-DD HH:MM:SS` (UTC, no timezone
  suffix). Render as-is or append `Z` after parsing; do not assume ISO-8601 with an offset.
- `null` is possible on `updated_at`, `authenticated_at`, `description`, `client_id` (role),
  `name` (user), `detail` (audit entry). Every one of these is nullable.
- Booleans on write accept `true`/`false`, `1`/`0`, `"true"`/`"false"`. Anything else is a
  `400`. A value that is not a recognised boolean never gets coerced.
- All ids are UUID strings.

---

## 4. Endpoint summary

`/admin` prefix on everything below. All rows need the auth header from §1.

| Resource | Endpoints |
|---|---|
| Keys | `POST /keys` |
| Realms | `GET /realms`, `POST /realms`, `GET/PUT/DELETE /realms/{id}` |
| Clients | `GET /clients`, `POST /clients`, `GET/PUT/DELETE /clients/{id}` |
| Users | `GET /users`, `POST /users`, `GET/PUT/DELETE /users/{id}` |
| User roles | `GET/POST /users/{id}/roles`, `DELETE /users/{id}/roles/{role_id}` |
| Scope-role maps | `GET/POST /clients/{id}/scope-roles`, `PUT/DELETE /clients/{id}/scope-roles/{scope}/{role_id}` |
| Roles | `GET /roles`, `POST /roles`, `GET/PUT/DELETE /roles/{id}` |
| Sessions | `GET /sessions`, `DELETE /sessions/{id}`, `POST /sessions/invalidate` |
| Logins | `GET /logins`, `DELETE /logins/{id}` |
| Offline sessions | `GET /offline-sessions`, `GET /offline-sessions/{id}`, `DELETE /offline-sessions/{id}` |
| Audit log | `GET /audit-logs`, `GET /audit-logs/{id}`, `DELETE /audit-logs` |
| Migrations (ops) | `POST /migrations/migrate`, `POST /migrations/rollback`, `POST /migrations/go`, `GET /migrations/status`, `GET /migrations/dry-run` |
| Maintenance (ops) | `POST /maintenance/cleanup` |

---

## 5. Resources

### 5.1 Realms

A realm owns keys, token TTLs, the scope set, and the password policy.

**`GET /admin/realms`** — no auth exception; **this is the one list that is not paginated**.
Returns a bare object, not the list envelope:

```json
{ "realms": [ /* realm objects */ ] }
```

Realm object (also the shape of `GET /realms/{id}` and the create/update response):

```json
{
  "id": "uuid",
  "name": "web",
  "keys_id": "uuid-of-the-key-set",
  "refresh_token_expires_in": 1800,
  "access_token_expires_in": 300,
  "pending_login_expires_in": 300,
  "authenticated_login_expires_in": 300,
  "session_expires_in": 86400,
  "idle_session_expires_in": 1800,
  "offline_refresh_token_expires_in": 2592000,
  "password_policy": {
    "min_length": 8, "min_lower": 0, "min_upper": 0, "min_digits": 1, "min_special": 1
  },
  "scope": "openid profile email",
  "created_at": "2026-08-01 10:00:00"
}
```

`scope` is a **single space-delimited string**, not an array — split on `" "` in the UI.
It is also the only catalog of available scopes; there is no scopes endpoint.

**`POST /admin/realms`** → `201`

| Field | Required | Default |
|---|---|---|
| `name` | **yes** | — |
| `keys_id` | **yes** | — (must exist; see keys endpoint) |
| `scope` | no | `openid profile email` |
| `refresh_token_expires_in` | no | `1800` |
| `access_token_expires_in` | no | `300` |
| `pending_login_expires_in` | no | `1800` |
| `authenticated_login_expires_in` | no | `1800` |
| `session_expires_in` | no | `86400` |
| `idle_session_expires_in` | no | `1800` |
| `offline_refresh_token_expires_in` | no | `2592000` |
| `password_min_length` | no | `null` = inherit global config |
| `password_min_lower` | no | `null` = inherit |
| `password_min_upper` | no | `null` = inherit |
| `password_min_digits` | no | `null` = inherit |
| `password_min_special` | no | `null` = inherit |

All TTL fields are positive integers; `1` is the minimum. Password policy fields are
non-negative integers where `0` disables that rule, and `null` means inherit the global
`[password_policy]` config.

**`PUT /admin/realms/{id}`** → `200`, partial update, all fields optional, absent fields keep
their current value. Password policy fields have a deliberate three-way rule:
**absent = keep current**, **explicit `null` = reset to inherit**, **integer = set** (with `0`
disabling). This is the only way to clear an override, so the UI must send the field
explicitly as `null` rather than omitting it.

**`DELETE /admin/realms/{id}`** → `204`. Refuses with `409` whilewhile the realm still has anyany
clientclient or any user. Roles are not checkedany user. Roles are not checked.

### 5.2 Keys

**`POST /admin/keys`** → `201`

No body. Generates an RSA key pair on disk and returns:

```json
{ "kid": "uuid-of-the-new-key-set" }
```

Feed the returned `kid` into `keys_id` when creating a realm. **This endpoint is not
idempotent** — calling it twice creates two key sets. Use check-then-create.

### 5.3 Clients

```json
{
  "id": "uuid",
  "name": "spa",
  "realm_id": "uuid",
  "uri": "http://localhost:5173/*",
  "require_auth": true,
  "scope": "openid profile email",
  "has_secret": true,
  "created_at": "2026-08-01 10:00:00"
}
```

`require_auth` is the confidential flag: `true` means the client must authenticate with a
secret (server-side `client_credentials`), `false` means public (browser, PKCE).

**`POST /admin/clients`** → `201`

| Field | Required | Notes |
|---|---|---|
| `name` | **yes** | |
| `uri` | **yes** | redirect URI pattern; `(name, uri)` is unique |
| `realm_id` | **yes** | must exist |
| `require_auth` | no | default `false` |
| `client_secret` | conditional | **required when `require_auth: true`**; must be absent when `false` |
| `scope` | no | `null` = inherit the realm scope |

> **The secret is write-only and is never returned by any endpoint** — not on create, not on
> read, not on update. The response only carries the `has_secret` boolean. So the dashboard
> must make the operator **type or generate the secret at creation time**; there is no
> "copy it once from the response" flow. Rotation is a `PUT` with a new `client_secret`.

`409` cases: a `client_secret` on a public client; a confidential client without one.

**`PUT /admin/clients/{id}`** → `200`, partial. `client_secret` rotates the secret when sent.
Demoting to public (`require_auth: false`) silently clears the stored secret. Promoting to
confidential requires a `client_secret` in the same call, or `409`.

**`DELETE /admin/clients/{id}`** → `204`, `409` while the client has active logins or active
offline sessions.

### 5.4 Users

```json
{
  "id": "uuid",
  "realm_id": "uuid",
  "name": "Jane",
  "email": "jane@example.com",
  "valid": true,
  "email_verified": true,
  "created_at": "2026-08-01 10:00:00"
}
```

`valid: false` is the deactivate switch — the user can no longer authenticate, but the row
stays. `name` is nullable.

**`POST /admin/users`** → `201`

| Field | Required | Notes |
|---|---|---|
| `realm_id` | **yes** | |
| `email` | **yes** | unique per realm |
| `password` | **yes** | sent as **plaintext**, hashed server-side; must satisfy the realm password policy or `400` |
| `name` | no | nullable |
| `valid` | no | default `true` |
| `email_verified` | no | default `true` |

**`PUT /admin/users/{id}`** → `200`, partial. Omit `password` to leave it unchanged; send one
to change it (this is also the admin-only password reset). Sending `realm_roles` returns
`400` — that field was removed; roles are entities now (§5.5).

**`DELETE /admin/users/{id}`** → `204`, `409` while the user has an active sessionsession or an
active offline session. (Logins are not checked; they go with the sessions.)

### 5.5 Roles and user-role assignment

Roles are either realm roles (`client_id: null`) or client roles (`client_id` set).

```json
{
  "id": "uuid", "realm_id": "uuid", "client_id": null,
  "name": "editor", "description": null, "created_at": "2026-08-01 10:00:00"
}
```

**`POST /admin/roles`** → `201` — `realm_id` (required), `name` (required), `client_id`
(optional, omit for a realm role), `description` (optional).
**`PUT /admin/roles/{id}`** → `200` — `name` and/or `description`.
**`DELETE /admin/roles/{id}`** → `204`.

**`GET /admin/users/{id}/roles`** → list envelope of role objects.
**`POST /admin/users/{id}/roles`** → `201`, body `{ "role_id": "uuid" }`, returns the assigned
role. The role must belong to the same realm as the user, else `400`.
**`DELETE /admin/users/{id}/roles/{role_id}`** → `204`. **Idempotent** — removing an assignment
that does not exist still returns `204`, not `404`. The UI can send it freely.

### 5.6 Scope-to-role mappings (per client)

Ties a client scope to a client role, so granting the scope in a token grants the role.
Shape is flatter than a normal object because it is a join row:

```json
{ "scope": "openid", "role_id": "uuid", "role_name": "editor", "required": false }
```

- **`GET /admin/clients/{id}/scope-roles`** → list envelope.
- **`POST /admin/clients/{id}/scope-roles`** → `201`, body `{ "scope": "...", "role_id": "...", "required": false }`. Both `scope` and `role_id` are required; the scope must be valid for that client (present in the client's own `scope`, or inherited from its realm) or `400`. TheBoth `scope` and `role_id` are required; the scope must be valid for that client (present in the client's own `scope`, or inherited from its realm) or `400`. The `{scope, role_id}` pair is unique, so a second POST for the same pair is a `409` — the UI should check the list first or treat `409` as "already mapped".
- **`PUT /admin/clients/{id}/scope-roles/{scope}/{role_id}`** → `200`, body `{ "required": true }`. Only `required` is updatable; to change the pair, delete and recreate. The response is `{ "scope": ..., "role_id": ..., "required": ... }` — **it omits `role_name`** even though the list includes it.
- **`DELETE /admin/clients/{id}/scope-roles/{scope}/{role_id}`** → `204`, idempotent.

`{scope}` goes in the path verbatim — encode it (`openid` is safe, a scope with unusual
characters must be percent-encoded).

### 5.7 Sessions, logins, offline sessions

**`GET /admin/sessions`** → list envelope; filters `realm_id`, `user_id`.

```json
{
  "id": "uuid", "realm_id": "uuid", "user_id": "uuid",
  "acr": "0", "status": "ACTIVE",
  "created_at": "2026-08-01 10:00:00", "updated_at": "2026-08-01 10:05:00"
}
```

`status` is `ACTIVE` or `EXPIRED`. `acr` is an authentication-context string, `"0"` meaning
no special context. `updated_at` is nullable.

**`DELETE /admin/sessions/{id}`** → `204`, revokes the SSO session (cascades to its logins).
**`POST /admin/sessions/invalidate`** → `200` with `{ "invalidated": 7 }`. Body needs at least
one of `user_id`, `client_id` — `400` if both are missing. With only one, it invalidates
everything for that subject; with both, only the intersection. This is the bulk "log this
user out everywhere" action.

**`GET /admin/logins`** → list envelope; filters `realm_id`, `client_id`.

```json
{
  "id": "uuid", "client_id": "uuid", "session_id": "uuid",
  "scope": "openid profile email",
  "status": "AUTHENTICATED",
  "created_at": "...", "authenticated_at": "...", "updated_at": "..."
}
```

`status` is one of `PENDING`, `AUTHENTICATED`, `ACTIVE`, `EXPIRED`. `authenticated_at` and
`updated_at` are nullable. **A login is an auth attempt, not a session** — this list is the
right place for a "sign-in activity" view; use `/sessions` for "who is logged in".

**`DELETE /admin/logins/{id}`** → `204`.

**`GET /admin/offline-sessions`** → list envelope; filters `realm_id`, `user_id`, `client_id`.
**`GET /admin/offline-sessions/{id}`** → single object.

```json
{
  "id": "uuid", "realm_id": "uuid", "user_id": "uuid", "client_id": "uuid",
  "acr": "0", "scope": "openid offline_access",
  "status": "ACTIVE",
  "created_at": "...", "authenticated_at": "...", "updated_at": "..."
}
```

The offline `id` doubles as the SSO `sid` claim. **Important semantic: `DELETE` here is a
soft revoke** — the row is marked expired, not erased, and stays visible in the list with
`status: "EXPIRED"`. Label the button "Revoke", not "Delete".

### 5.8 Audit log

Every admin write on realms, clients, users, roles and scope-role mappings is recorded.

```json
{
  "id": "uuid",
  "action": "client.create",
  "actor_type": "admin_user",
  "actor_id": "uuid-or-null",
  "realm_id": "uuid-or-null",
  "target_type": "client",
  "target_id": "uuid-or-null",
  "detail": { "...": "the request payload as JSON, or null" },
  "created_at": "2026-08-01 10:00:00"
}
```

`action` is one of: `realm.create`, `realm.update`, `realm.delete`, `client.create`,
`client.update`, `client.delete`, `user.create`, `user.update`, `user.delete`, `role.create`,
`role.update`, `role.delete`, `scope_role.create`, `scope_role.update`, `scope_role.delete`.

`actor_type` is exactly one of `admin_user` (a JWT admin logged in) or `api_key` (the static
key) — use it to badge the origin of a change. `actor_id` is the JWT `sub` claim and is `null`
for the static key. `detail` is the request payload as a JSON object, merged with identifiers
taken from the route, and `null` when there was nothing to record. **`password` and
`client_secret` are replaced with `"***"` before storage**, so a secret never reaches this log.
**Treat `detail` as untyped and version-unstable** — display it, never parse it into a form.

- **`GET /admin/audit-logs`** → list envelope. Filters `action`, `actor_type`, `target_type`,
  `realm_id`, `from`, `to`. `from`/`to` are bare `YYYY-MM-DD` dates; `to` is inclusive (it is
  extended to end-of-day server-side). An unparseable or impossible date is a `400`.
- **`GET /admin/audit-logs/{id}`** → single entry.
- **`DELETE /admin/audit-logs`** → `200` with `{ "deleted": 12 }`. Body **must** carry at
  least one of `realm_id` or `older_than` — `400` otherwise, so a purge can never be
  accidental and unbounded. `older_than` is `YYYY-MM-DD`. A delete with no body still works
  if either field is passed as a query param.

### 5.9 Ops endpoints

Ops endpoints are the ones that keep working with the static API key once dual-mode is
narrowed. They are not part of the normal dashboard UX; expose them only if you want an ops
page.

- **`POST /admin/maintenance/cleanup`** → `200`:

```json
{ "blacklist_purged": 3, "logins_purged": 12, "sessions_purged": 4, "offline_sessions_purged": 0 }
```

Purges expired rows only. Safe to run repeatedly.

- **Migrations** — `POST /migrate`, `POST /rollback`, `POST /go`, `GET /status`,
  `GET /dry-run` under `/admin/migrations`.

| Endpoint | Query params | Response |
|---|---|---|
| `POST /migrate` | — | `{ "applied": [{ "version": 9, "name": "audit_logs" }], "count": 1 }` |
| `POST /rollback` | `steps` (default 1) | `{ "rolled_back": [...], "count": 1 }` |
| `POST /go` | `version` (**required**, `>= 0`) | `{ "applied": [...], "count": 1, "target": 9 }` |
| `GET /status` | — | `{ "migrations": [ ... ], "count": 9 }` |
| `GET /dry-run` | — | `{ "pending": [ ... ], "count": 0 }` |

`POST /go` without `version` is a `400` with `error: "invalid_version"`.

---

## 6. Endpoints that need no admin token

Useful for status indicators. None of these carry the §1 header requirement.

| Endpoint | Response |
|---|---|
| `GET /health` | `{ "status": "ok" }` — liveness, does not touch the database |
| `GET /ready` | `{ "status": "ok" }`, or `503` `{ "error": "database_unreachable", "error_description": "..." }` |
| `GET /realms/{realm}/.well-known/openid-configuration` | OIDC discovery document |
| `GET /realms/{realm}/protocol/openid-connect/certs` | JWKS |
| `GET /realms/{realm}/protocol/openid-connect/userinfo` | needs a *user* access token in the same header, not an admin token |

### Not part of the application

`/admin/db` is a database administration tool, not an application feature. It has its own
password and is intentionally kept outside the application, so it is out of scope for this
contract. The one rule that matters here: **do not link it from the dashboard.**

---

## 7. Behaviour the UI must get right

1. **The realms list is the odd one out** — `{ "realms": [...] }`, unpaginated. Either special-case it in the table layer or wait for it to be aligned. If the backend aligns it to the standard envelope, treat that as a breaking change and pin your version of this doc.
2. **Read `limit` back from the response** instead of trusting what you sent — out-of-range values silently become the default.
3. **Never render a client secret from an API response.** It does not exist. Generate it in the form at creation time and show it to the operator once, client-side.
4. **Passwords go over the wire as plaintext** and are hashed server-side. Send them only over TLS, and never log or persist them in the browser.
5. **Idempotent deletes**: removing a user-role assignment or a scope-role mapping always returns `204`. Real "does not exist" `404`s only happen on the `GET /{id}` and resource `DELETE` routes.
6. **Distinguish the three session-ish resources**: `logins` = auth attempts, `sessions` = SSO logins, `offline-sessions` = long-lived refresh grants that survive SSO logout.
7. **Offline-session delete is a revoke**, and expired rows remain listable with `status: "EXPIRED"`.
8. **Guard destructive calls with a confirm step**: audit-log purge (`DELETE /admin/audit-logs`) and realm delete are the two that lose data.
9. **A `409` is usually actionable, not fatal** — surface `error_description` verbatim; it names the blocking thing ("client 'x' still has active offline sessions").
10. **`allowed_origins` is `*` in dev but must be pinned** to the real dashboard origin before any shared or public deployment, otherwise any origin can read the admin API with a token it captured.

---

## 8. Known gaps to raise, not to work around

| Gap | Impact | Status |
|---|---|---|
| `GET /admin/realms` not paginated, different envelope | realms table needs a special case | queued, small |
| No search on users or clients | cannot look a user up by email or a client up by name | F-53 — **prefix type-ahead**, so the UI should send the start of the term and expect prefix matches. The server escapes `%` and `_`, so send the term verbatim: a literal `100%` matches `100%`, and typing `%` will not match everything |
| Audit log cannot be filtered by `target_id` | no per-resource history view; you can only ask for "all client events" | F-56 — `?target_id=`, index already exists |
| No statistics or count endpoint | a dashboard home page must fan out several list calls and read `total` | not queued — raise if wanted |
| No bulk create/update/delete | bulk UI actions must loop client-side | by design |
| Audit `detail` payload shape is unstable | display only | by design |
