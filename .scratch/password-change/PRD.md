# Admin Credential Rotation — change-password & change-client-secret (admin API only)

> **Status: superseded.** F-50 shipped without new endpoints — rotation works
> through `PUT /admin/users/{id}` (with session revocation) and
> `PUT /admin/clients/{id}` (with the client/secret invariant). The original
> problem statement below was stale: both `PUT`s already supported the
> mutations. See `## Comments` and `issues/01-rotate-via-put-invariants.md`.

## Problem

Admin credentials are seeded as static argon2id hashes baked into `db/seed.sql` (admin
user password + `ci-deployer` client secret). That is fine for dev-only seed, but there is
**no way to rotate either** without hand-writing a hash — the admin API only creates users
and clients; it cannot change their password/secret after the fact. This is a real ops gap:

- The prod bootstrap runbook (`admin-auth/release-plan.md`) generates strong bootstrap
  values, but they become **permanent** — the release plan explicitly accepts this until
  change endpoints exist.
- Any credential leak, personnel change, or routine rotation is blocked until delete +
  recreate.
- `ci-deployer` will be the end-state auth for CI migrations/cleanup (F-49); a secret with
  no rotation path is a standing risk.

## Goals

1. **Admin resets a user's password** via the admin API. The client sends **plaintext**
   only; the server hashes server-side (reuse the existing argon2id path —
   `SecretsService` / `password_hash`). Callers never hand a pre-hashed value.
2. **Admin rotates a client's secret** for confidential clients (e.g. `ci-deployer`) via
   the admin API, with the same hashing discipline.
3. Standard response safety: the API never echoes the new plaintext or hash back.
4. Scope: **admin-only v1**. No self-service password change / forgot-password in this PRD.

## Non-goals

- Self-service password change, reset-password, or forgot-password flows (future, separate
  feature on top of these primitives).
- Password policy enforcement / complexity rules (per-realm password policy is F-11).
- Force-change-on-next-login enforcement (flagged as optional below).
- Removing or re-hashing the static `api_key` (that is F-48/F-49 territory).
- Rotation of RSA signing keys (that is `POST /admin/keys` + realm `keys_id` reassignment,
  out of scope).

## Approach

Both endpoints follow the pattern already established by `POST /admin/users` /
`POST /admin/clients`: validate, hash plaintext server-side via `SecretsService`, persist,
return the public representation only. Additive under the existing `AdminMiddleware`
(`api_key` today, JWT via F-48 next) — no auth change needed.

### Endpoint: change user password

```
PATCH|POST /admin/users/{id}/password
{ "password": "<plaintext>" }
```

- Hashing: `SecretsService::hashPassword()` (same argon2id config as create).
- Persistence: `UserRepository::updatePassword()` (new method; typed, no logger).
- Response: `204` (no body) — or `200` with the public user representation, matching repo
  convention. Never echo the plaintext or the hash.
- Validation: existing user (404), non-empty / policy-checked password (reuse create rules).

### Endpoint: change client secret

```
PATCH|POST /admin/clients/{id}/secret
{ "secret": "<plaintext>" }
```

- Only meaningful for confidential clients. Either reject a call on a public client
  (`require_auth = 0`, `client_secret IS NULL`) with 409/422, or store a hash; decide in
  the issue. I lean **reject** — it keeps the "public = no secret" invariant honest.
- Hashing: `SecretsService::hashPassword()`, persisted via a new
  `ClientRepository::updateSecret()`.
- Response: `204`. The client's public shape already exposes `has_secret` only
  (`ClientsController::toArray`); unchanged.

### Revocation considerations (decide in issues)

- Changing a user password: should it revoke that user's active SSO sessions /
  `offline_sessions`? Rotating a password is usually defensive → growing existing
  `invalidate` machinery is likely correct. Confirm in the issue; do not silently ship
  without deciding.
- Changing a client secret: issued JWTs are stateless and unaffected; future
  `client_credentials` / refresh-with-secret calls fail until the caller adopts the new
  secret. No server-side invalidation needed, but document it.

### Temporary stopgap (until the endpoints ship)

A small CLI script (`bin/hash-password.php`) that takes plaintext and prints a valid
argon2id hash, so an operator can hand-write a hash into the DB via Adminer/`sqlite3`.
Dev/ops convenience only; **superseded** by the admin-API endpoints — it must not outlive
them as a supported path.

## Security

- Plaintext only ever over TLS; hashed at rest; never logged.
- Same argon2id discipline as create/verify today (`SecretsService`).
- No pre-hashed input accepted — server always hashes the caller-provided plaintext.
- Rotation should be auditable (note where the existing audit log hooks in, F-07 pending).

## Phased delivery

- **01** — change-password admin endpoint (M)
- **02** — change-client-secret admin endpoint (S)
- **03** — temp argon2id hash CLI stopgap (S, optional / dev-only)

## Comments

### 2026-08-30 — F-50 implemented without new endpoints (supersedes Approach + Phased delivery)

Investigation against the current code showed the PRD's problem statement was
stale: `PUT /admin/users/{id}` already accepts a new `password` (hashed
server-side, no current password required) and `PUT /admin/clients/{id}`
already accepts a new `client_secret`. Both were added by later admin-CRUD
work. Adding the dedicated action endpoints from the PRD would have created a
second mutation path per resource, so the decision (grilled with the user) was:

- **No new endpoints.** Rotation happens through the existing `PUT` resources.
- **Password rotation revokes sessions**: `PUT /admin/users/{id}` with a new
  password deletes the user's sessions+logins and expires their offline
  refresh grants. Revocation logic extracted from `SessionsController` into
  `SessionRevocationService` (single home, reused by invalidate/delete).
- **Client invariant enforced in `POST`/`PUT /admin/clients`**: confidential
  ⇒ has secret, public ⇒ no secret (409 otherwise); promotion requires the
  secret in the same call; demotion auto-clears the stored secret.
- **`ClientAuthenticator` fails closed** on confidential clients with a
  missing stored hash (previously a TypeError/500 on legacy rows).
- PRD issues #01/#02 are superseded by this decision; #03 (CLI stopgap) is
  dropped as born-superseded. Details:
  `issues/01-rotate-via-put-invariants.md`.