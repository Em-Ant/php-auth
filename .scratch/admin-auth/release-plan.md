# Release plan — Admin realm bootstrap via Admin API

- **Date:** 2026-08-28
- **Risk class:** low, operator-discipline only (additive API-driven bootstrap; no code
  change — all endpoints already exist behind `AdminMiddleware`). The one footgun is the
  non-idempotent `POST /admin/keys` step; it is handled by check-then-create discipline.
- **Related:** `admin-auth/PRD.md` (Phase 1/2), realm-create-keys decision (below),
  `docs/adr/0002` (risk taxonomy)

## What changed and why

Prod **never runs `db/seed.sql`** (dev-only, AGENTS.md). So the `admin` realm + role +
clients + bootstrap admin user that F-47 seeds into dev must be driven into a **live prod
DB** through the admin API instead. This plan is the repeatable, scripted runbook for that
bootstrap, authenticated with the static `api_key`. It depends on **no code change**.

All steps use the **existing** admin endpoints behind `AdminMiddleware`
(`src/App/AppBuilder.php:297,309-371`). Keys are created explicitly via `POST /admin/keys`
and the returned `kid` is passed as `realms.keys_id` — **no** auto-keygen is being added to
`RealmsController::create` (it still validates `keys_id` via `assertKeysExist` and never
mints keys). See **Realm-create-keys decision** below for why.

## Pre-flight check (run BEFORE bootstrap)

1. Server deployed; `config.ini [admin] api_key` set and known to the operator.
2. Admin API reachable over TLS, e.g. `https://auth.example.com/admin/...`.
3. DB migrations applied: `POST /admin/migrations/migrate` (already `api_key`-authenticated).
4. `keys/` directory on the server is on a **persistent volume** (see _Operational issues_
   #1) and writable by the app.

Idempotency safety: every create step below must be **check-then-create** — `GET` the
resource by name first and skip if present (realm `name` is UNIQUE; user `(email, realm_id)`
is UNIQUE; client `(name, uri)` is UNIQUE). A partial failure mid-run must not leave a
half-bootstrapped realm; a blind re-`POST /admin/realms` returns 409
(`ConflictException`).

## Bootstrap script (fill in the variables at the top)

A single self-contained bash script. **You must fill in `BASE_URL` and `API_KEY`**; the optional
overrides already default to values matching the dev seed (realm scopes, client names/URIs,
token TTLs). Secrets are auto-generated (`openssl rand`) if left empty and printed once —
they are **not** retrievable afterwards. The script is **idempotent**: every resource is
checked before being created, so a partial or repeated run is safe.

The canonical script is committed at
[`issues/bootstrap-admin-realm.sh`](issues/bootstrap-admin-realm.sh). Make it executable,
fill in the variables, then run:

```bash
chmod +x issues/bootstrap-admin-realm.sh
./issues/bootstrap-admin-realm.sh
```

Notes on the script:

- The server hashes `password` / `client_secret` server-side
  (`UsersController.php:87`, `ClientsController.php:190` → `SecretsService::hashPassword`).
  The script sends **plaintext** — never pre-hashed values — over TLS.
- **Secrets are final until F-50 ships** (`password-change/PRD.md`). If you re-run with
  `ADMIN_PASSWORD`/`CI_SECRET` unset, they are regenerated but **not** re-applied (the checks
  skip existing rows) — only the first run's printed values matter. To rotate, use the F-50
  change endpoints once they land, or delete + recreate before re-running.
- The role lookup lists roles scoped by `realm_id` and then keeps only `client_id == null`
  (realm roles) via jq; user/role/client lookups are all `realm_id`-scoped, so a same-named
  row in another realm can't satisfy the check.
- The only non-idempotent call (`POST /admin/keys`) is guarded by the "realm missing"
  branch — re-running never mints extra keys. Every resource check uses jq's `first(...)`,
  which exits 0 on no-match (so the `set -euo pipefail` script doesn't abort on the happy
  "already exists" path) and yields an empty `ID` that triggers creation.

## Post-bootstrap state

The `admin` realm exists and `GET /realms/admin/protocol/openid-connect/certs` serves JWKS.
But **Admin API still rejects JWTs** until F-48 (`AdminAuthMiddleware`) ships — so today the
realm is inert for API auth; `api_key` remains the only working admin auth. The seeded data
is ready the instant F-48/F-49 land.

## Post-deploy verification (ordered)

1. **JWKS exposed for the admin realm**

   ```bash
   curl -s https://auth.example.com/realms/admin/protocol/openid-connect/certs
   # expect keys[] with the kid from step 1
   ```

2. **Realm present in the admin list**

   ```bash
   curl -s -H "X-Admin-Key: $API_KEY" https://auth.example.com/admin/realms \
     | jq '.[] | select(.name=="admin")'
   ```

3. **JWT against Admin API still rejected until F-48** (expected)

   ```bash
   # attempt an access token for the admin realm against /admin/* → expect 401
   ```

   Until F-48, `api_key` remains required; a 401 here confirms the middleware is unchanged
   (the JWT branch does not exist yet).

## Local test results (2026-08-28)

The script was exercised against a **real** server and SQLite DB before shipping:

- **Environment:** fresh local DB with **migrations only** (`rm db/data.db && composer
  migrate`) so no `admin` realm pre-existed; dev server `localhost:8000`; real `api_key`
  from `config.ini` (`dev-admin-token-change-me`).
- **Fresh run -> exit 0.** Created keys -> realm -> role (`client_id NULL`) -> admin user
  (argon2id hash, 96 chars) -> role assignment -> both clients. Verified:
  - realm `scope = openid profile email offline_access`
  - `admin-ui`: `require_auth=0`, no secret; `ci-deployer`: `require_auth=1`, `has_secret=1`
  - admin user carries `basic` + `admin` roles
  - JWKS served the new `kid` at `/realms/admin/protocol/openid-connect/certs`
- **Repeat run -> exit 0 (idempotent).** Reused the same realm/role/user/client IDs, printed
  "already exists" for each, **no** new keys minted, no duplicates. The only re-executed
  mutation is the role assignment (server-side `INSERT OR IGNORE`).
- The test DB was restored afterward; the ephemeral key dir it created was removed.

This proves the recovery story: on a partial or repeated run the script skips existing
resources instead of erroring, so an operator can re-run it safely.

## Operational issues

1. **Keys are filesystem, not DB.** `POST /admin/keys` writes `keys/<kid>/`
   (`public_key.pem`, `private_key.pem`, `cert.pem`, `keys.json`) on the server. The
   `realms.keys_id` row only references the dir. If the `keys/` volume is wiped/lost, the
   realm's certs/JWT verification break even though the DB row exists. → Keep `keys/` on a
   persistent, backed-up volume; treat key material as prod secrets.

2. **`api_key` has full admin scope** during bootstrap (can create realms, users, clients —
   wider than the eventual offline-token CI). Acceptable interim (PRD Phase 3). Plan to
   narrow then remove `api_key` once `ci-deployer` offline tokens ship (F-49).

3. **Plaintext over TLS, hashed at rest.** User password and `client_secret` are sent
   plaintext and hashed server-side (verified). The script must send **strong, randomly
   generated** values — never the dev hashes from `seed.sql`. Store the generated
   `ci-deployer` secret in the CI secret manager; it is shown only once (the API never echoes
   it back: `ClientsController::toArray` returns only `has_secret`, and
   `UsersController::toArray` omits `password`).

4. **Bootstrap secrets are final until change endpoints ship.** `change-password` and
   `change-client-secret` admin endpoints do **not** exist yet (see `password-change/PRD.md`).
   The admin user password and `ci-deployer` secret set here are permanent until those land.
   Mitigation: generate strong values now; rotate by re-running the bootstrap (delete +
   recreate client/user) once the change endpoints exist.

## Realm-create-keys decision (recorded 2026-08-28)

`RealmsController::create` (`src/Controllers/Admin/RealmsController.php:57`) requires the
caller to supply `keys_id` and validates it via `assertKeysExist`; it never mints keys. Auto-
keygen (making `keys_id` optional on realm create) is **NOT** being added — this plan handles
bootstrap by calling `POST /admin/keys` first and passing the returned `kid`. Auto-keygen
stays OPTIONAL / deferred (ergonomics only); revisit only if a one-call realm bootstrap is
ever wanted.

## Open items / dependencies

- F-48: `AdminAuthMiddleware` (JWT + role) — makes the seeded realm actually authorize.
- F-49: migrate CI from `api_key` to `ci-deployer` offline token; then narrow/remove `api_key`.
- F-50 (`password-change/PRD.md`): change-password + change-client-secret endpoints — rotate
  the bootstrap secrets without deleting/recreating.
