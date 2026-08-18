# Admin API — realm/client/user management

## Problem Statement

Today the only programmatic way to configure realms, clients, and users is the
DB browser (Adminer at `/admin/db`) or raw SQL. The OIDC surface is fully
built out (auth, token, revoke, introspect, logout) but there is no
first-class, authenticated API to manage the entities it serves. This blocks
every admin-side roadmap item: offline revocation, password policy, scope/role
configuration, audit queries.

## Goals

A Bearer-protected admin API (same `AdminMiddleware` + `X-Admin-Key` /
`Authorization: Bearer` as the migrations API) covering:

1. **Realms** — CRUD + key assignment (`keys_id`).
2. **Clients** — CRUD per realm.
3. **Users** — CRUD per realm (secrets hashed, never returned).
4. **Keys** — explicit key-pair generation (the `kid` assigned to realms).

## Contract

All endpoints live under `/admin`, JSON in/out, protected by
`AdminMiddleware`. Error shape follows `JsonResponse::error`:
`{error, error_description}`.

| Method | Path | Description |
|---|---|---|
| POST | `/admin/keys` | Generate a new RSA key pair → `{kid}` |
| GET | `/admin/realms` | List realms |
| POST | `/admin/realms` | Create realm (`keys_id` required) |
| GET | `/admin/realms/{id}` | Read realm |
| PUT | `/admin/realms/{id}` | Update realm (partial: provided fields only) |
| DELETE | `/admin/realms/{id}` | Delete realm (409 if clients/users exist) |
| GET | `/admin/clients` | List clients (`?realm_id=` filter) |
| POST | `/admin/clients` | Create client |
| GET | `/admin/clients/{id}` | Read client |
| PUT | `/admin/clients/{id}` | Update client (partial) |
| DELETE | `/admin/clients/{id}` | Delete client (409 if logins exist) |
| GET | `/admin/users` | List users (`?realm_id=` filter) |
| POST | `/admin/users` | Create user |
| GET | `/admin/users/{id}` | Read user |
| PUT | `/admin/users/{id}` | Update user (partial) |
| DELETE | `/admin/users/{id}` | Delete user (409 if active sessions exist) |
| GET | `/admin/sessions` | List sessions (`?realm_id=`, `?user_id=` filter) |
| DELETE | `/admin/sessions/{id}` | Delete session (cascades login deletion) |
| POST | `/admin/sessions/invalidate` | Invalidate sessions by `user_id` or `client_id` (marks ACTIVE → EXPIRED) |
| GET | `/admin/logins` | List logins (`?realm_id=`, `?client_id=` filter) |
| DELETE | `/admin/logins/{id}` | Delete a single login |

### Key assignment

Keycloak-style realms own a signing key (`realms.keys_id`). This API makes the
assignment explicit:

1. `POST /admin/keys` generates a fresh RSA key pair into the configured key
   store and returns `{kid}`.
2. Realm create **requires** `keys_id` (validated to exist in the keystore);
   realm update may re-assign it.

### Security

- **Secrets never leave the API**: user `password` and client `client_secret`
  are write-only. Responses return `has_secret` instead of the hash.
- Passwords and client secrets are hashed with `SecretsService` (argon2id,
  config-driven) before storage — same path as the OIDC flows.
- Deletes are guarded: a realm with clients/users, a client with **active**
  logins, or a user with **active** sessions returns **409 Conflict** instead
  of orphaning FK references. Expired/completed logins and sessions no longer
  block deletion.
- Duplicates (realm name, client name+uri, user email within a realm) return
  **409 Conflict** via pre-checks, not a 500 from the UNIQUE constraint.

### Validation

`ValidationFailed` → 400. Required fields and positive-int timer constraints
are checked in the controllers. PUT is partial-update: only fields present in
the body are changed.

### User deactivation

Users can be disabled by setting `valid = 'FALSE'` via `PUT /admin/users/{id}`.
Disabled users cannot authenticate — the OIDC login flow returns
`"user is disabled"` before credential verification. The `valid` field is
exposed in read responses as a string (`'TRUE'`/`'FALSE'`).

### Session & login management

Sessions track browser sessions (one per user); logins track individual
client authentications within a session. Invalidating a session marks all its
logins as EXPIRED. Deleting a session cascades to delete its logins.

Delete guards now only count **active** resources: a client with only expired
logins can be deleted, as can a user with only expired sessions.

## Decisions

- **`keys_id` required on realm create.** Explicit over magic: the admin
  generates keys (`POST /admin/keys`) then assigns. No hidden filesystem
  writes inside realm creation.
- **PUT = partial update.** Matches the "edit one field" admin workflow and
  avoids forcing full payloads.
- **Controllers in `src/Controllers/Admin/`**, routes wired in
  `public/index.php` (per AGENTS.md: admin endpoints live alongside public
  routes, not in a separate router).
- **No new migrations.** Realms/clients/users tables already exist; the
  feature is purely a read/write API over them.
- **`TokenService::createKeys()` gains a `$keysRoot` param + returns the
  `kid`** so the keys endpoint honors the configured `keys_root` and the
  generated id is observable.

## Out of Scope (follow-ups, see ROADMAP "Admin API")

- Audit log table + query (F-07)
- Per-realm password policy (F-11)
- Scope/role config surface (scopes #04)
- Offline revocation (F-06) and blacklist/session cleanup (F-19)

## Issues

- [#01](issues/01-admin-crud.md) — Admin CRUD: realms, clients, users, key assignment
- [#02](issues/02-session-login-management.md) — Session/login management, user deactivation, active-only delete guards
