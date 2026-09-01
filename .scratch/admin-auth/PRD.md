# Admin Auth & Tools — admin realm + JWT for Admin API, api_key interim → offline token end-state

## Problem

Admin API (`/admin/*`, `src/App/AppBuilder.php:295`) is protected by a single static secret (`config.ini [admin] api_key`, `src/Config/Definitions.php:88`, `src/Middleware/AdminMiddleware.php:15` accepting `Bearer <key>` or `X-Admin-Key`). This blocks:

- A separate Admin UI repo (React+Vite+shadcn) that should log in via OIDC code+PKCE — no user/role concept today.
- Least-privilege / auditability — one shared secret, no per-admin identity, no revocation.
- Future RBAC (audit log, password policy; realm_roles retirement done — F-45).

But ops/CI tasks — `POST /admin/migrations/*` and `F-19` blacklist/expired-session cleanup — must stay usable headless (no browser, no interactive login), via an **offline token** at end-state; **for now** the static secret stays as interim.

## Goals

1. Admin UI authenticates via **OIDC Authorization Code + PKCE** against an **admin realm** and calls Admin API with `Authorization: Bearer <access_token>` containing an admin role.
2. Admin API authorizes by **JWT + role check**, not just secret equality.
3. Migrations + cleanup remain usable from CI/deploy with a long-lived **offline JWT** (`scope=offline_access`, `offline_sessions`); interim, the static secret stays as fallback (narrowed scope) until offline flow is wired.
4. No breaking change on day one: existing `X-Admin-Key` callers keep working (interim); end-state is offline token only.

## Non-goals

- Full Keycloak-style `master` realm hierarchy or fine-grained per-resource policies.
- Building the React UI in this repo (separate repo; this PRD only defines the auth contract it consumes).
- Removing the static secret in this slice — it is interim for bootstrap/ops; removal/deprecation is Phase 3 / follow-up ADR (end-state: offline token only).

## Model

- **Admin realm**: seeded realm `admin` (name configurable, default `admin`) that owns admin users/clients/roles. Distinct from business realms (`web`, `test`). Supports **both SSO sessions and offline sessions** like any realm (`TokenGrantService.php:120` offline branch, `token-lifecycle/PRD.md` per-client `offline_sessions`). No special realm flag.
- **Admin role**: realm role `admin` (in `roles` table, `client_id IS NULL`, `realm_id = admin_realm.id`). Assigned via `POST /admin/users/{id}/roles`.
- **Admin clients** (per-client `clients.scope` gating via `ScopeResolver`, `scopes #02`):
  - `admin-ui` — public (PKCE, `authorization_code`), redirect URIs allow-listed, `clients.scope = "openid profile email"` — **no** `offline_access` by default. UI runs migrations/cleanup with the **short-lived access token** while user is present (normal SSO login, refresh via SSO session). `offline_access` for `admin-ui` only opt-in behind `prompt=consent` / explicit scope request (F-10 deferred) — not granted silently.
  - `ci-deployer` — confidential, `clients.scope` **includes** `offline_access` (realm `realms.scope` must also include it). Mints `offline_sessions` entries (`scope=offline_access` → `TokenGrantService` offline branch, survives SSO logout, revokable via `DELETE /admin/offline-sessions/{id}`, refresh via `grant_type=refresh_token`). This is the end-state for headless `POST /admin/migrations/*` + `POST /admin/maintenance/cleanup` (F-19).
- **Token claims**: access token carries `realm_access.roles` / `resource_access` as today (`src/Services/TokenService.php`, `ScopeResolver`). Admin check reads them + `iss`/`aud`/`exp`. Offline access tokens have `typ: Offline` (or `offline_access` scope claim) but still carry the same `admin` role — `AdminAuthMiddleware` accepts **both** SSO and offline access tokens identically after `TokenValidator` + role check.
- **Why both in one realm**: UI needs SSO (browser, PKCE, short TTL, no long-lived secret in storage); CI needs offline (no browser, long-lived, headless). One realm + two clients + one JWT auth path avoids a second auth system; gating is per-client scope, not per-realm.

## Contract

### Admin API auth (new)

`AdminAuthMiddleware` (replaces/augments `AdminMiddleware`):

1. Try `Authorization: Bearer <JWT>` (accepts **both SSO and offline** access tokens):
   - Validate via `TokenValidator` (issuer `config.ini [server] issuer`, keystore `keys/<kid>`, `exp`/`nbf`/`iss`/`aud`; offline tokens validated same path, `offline_sessions` TTL already enforced at mint/refresh).
   - Require `realm == admin` (token `iss` ends with `/realms/admin` or claim `realm`/`aud` — pick one canonical; propose `iss` check).
   - Require role `admin` in `realm_access.roles` (or `resource_access.admin-ui.roles` if we use client roles — keep realm role for v1).
   - On success → `200` path, `request` enriched with `admin_user` attribute for audit. No distinction between SSO vs offline at auth time.
2. Else try static secret `hash_equals(api_key, token)` from `Bearer` or `X-Admin-Key` **only if** request path is in allow-list: `/admin/migrations/*` and `/admin/maintenance/cleanup` (F-19) — **interim**. Outside allow-list → `401`. End-state: this branch is removed; only JWT (including offline) is accepted.
3. Else → `401 {error: unauthorized}` (same shape as today).

CORS: already via `allowed_origins` (`Definitions.php:93`); Admin UI origin must be listed.

**UI running migrations via PKCE**: `admin-ui` authenticates via PKCE code flow (SSO session, no `offline_access`), then `POST /admin/migrations/migrate` / `POST /admin/maintenance/cleanup` with the resulting access token — valid because middleware accepts any admin JWT. No offline token needed for user-present ops.

### OIDC for admin realm

No code change: existing `/realms/{realm}/protocol/openid-connect/{auth,token,certs,userinfo}` already realm-parameterized. Just seed `admin` realm + clients + role. Well-known `scope_supported` derived per-realm already (`scopes #01`).

For offline CI: `scope=offline_access` on `ci-deployer` (requires `clients.scope` includes it, and realm `scope` includes it) → `TokenGrantService` creates `offline_sessions` entry, refresh via `grant_type=refresh_token` survives SSO logout. `admin-ui` does **not** request `offline_access` by default (per-client scope gating); if UI later needs unattended migrations after tab close, add opt-in `offline_access` behind consent (F-10).

### Migration / bootstrap

- `composer setup` / `db/seed.sql` seeds `admin` realm, `admin` role, `admin-ui` + `ci-deployer` clients (dev-only; prod seed is manual/docs).
- If `admin` realm missing, static secret still bootstraps it (first `POST /admin/realms` with `X-Admin-Key`).

## Phased delivery

### Phase 1 — Admin realm + role + seed (S)
Seed `admin` realm/role/clients; no middleware change. Issue #01.

### Phase 2 — JWT auth middleware + dual-mode Admin API (M)
Implement `AdminAuthMiddleware`, wire in `AppBuilder::registerAdminRoutes()` (JWT group + narrowed static group), `Definitions` bindings, config. Issue #02. Includes `composer check` + unit/integration tests.

### Phase 3 — Migrate ops auth from api_key to offline token (S)
Interim narrow `X-Admin-Key` to `/admin/migrations/*` + `/admin/maintenance/cleanup` (F-19), **migrate** CI/deploy from `api_key` to offline JWT (`ci-deployer` + `scope=offline_access` → `offline_sessions` → `grant_type=refresh_token`), then remove `api_key` so end-state is **offline token only**. Issue #03. Depends on F-19 for cleanup endpoint shape.

## Security

- Static secret never logged; `hash_equals` stays.
- JWT `aud` must include `admin-ui` or `ci-deployer` (or realm) — prevents cross-realm token replay.
- Rate limiting on `/realms/admin/protocol/openid-connect/token` already via `rate_limiting.token_limit`.
- No new tables; reuse `roles` + `user_role_assignments` + `realms`/`clients`.

## Out of scope / deferred

- Fine-grained permissions (read vs write, per-realm admin).
- UI repo scaffolding.
- Full `api_key` removal ships as the tail of Phase 3 (follow-up ADR if needed).

## Issues

- #01 — Seed admin realm, role, and clients
- #02 — JWT admin auth middleware (dual-mode)
- #03 — Migrate ops auth from api_key to offline token
