# 02 — JWT admin auth middleware (dual-mode)

status: **DONE** 2026-08-30 (F-48) — uncommitted working tree (`src/Middleware/AdminAuthMiddleware.php`,
`src/Config/Definitions.php`, `src/App/AppBuilder.php`, `config.ini`, `bin/e2e-test.sh`,
`tests/Unit/Middleware/AdminAuthMiddlewareTest.php`, `tests/Integration/AdminAuthMiddlewareTest.php`;
`AdminMiddleware` deleted, `MigrationsEndpointTest` migrated). Deviations recorded under
Comments.

- New `AdminAuthMiddleware` (or rename `AdminMiddleware`): try JWT via `TokenValidator` (`issuer`, `exp`, `iss` → admin realm, `realm_access.roles` contains `admin`), then fallback to `hash_equals(api_key)` only on allow-listed ops paths. **Accept both SSO and offline access tokens** identically (no `typ` check; `offline_sessions` TTL already enforced at mint/refresh; `TokenValidator` covers both).
- Wire in `src/App/AppBuilder.php:295 registerAdminRoutes()` + `src/Config/Definitions.php:88`; keep `X-Admin-Key`/`Bearer api_key` compat outside allow-list → 401.
- Explicitly allow `admin-ui` PKCE access token to call `POST /admin/migrations/*` + `POST /admin/maintenance/cleanup` (F-19) — user-present ops need no offline token.
- Tests: unit (token valid/invalid/expired/wrong realm/missing role, SSO vs offline both pass/fail on role) + integration (admin JWT succeeds, non-admin JWT 401, static on non-ops 401, static on migrations 204).
- Must pass `composer check` (PHPStan 5, PSR12).

## Comments

- **2026-08-30 — review outcome.** Implemented as specified, with these recorded deviations:
  - **`allow_all` knob (interim, F-49).** Static fallback is restricted to the ops allow-list
    only when `[admin] allow_all = false` (Definitions: `admin_allow_all`). `config.ini` ships
    `allow_all = true` so realms/clients/users can be bootstrapped before the Admin UI JWT flow
    is ready — the spec's "ops-paths only" behavior is one config flip away.
  - **`typ` check.** `TokenValidator::validate(..., 'Bearer', null)` — stricter than the "no
    `typ` check" bullet. Safe: SSO and offline *access* tokens are both minted `typ: Bearer`
    (only refresh tokens carry `Offline`), so both pass identically, and refresh-token replay
    is excluded.
  - **Ops allow-list vs reality.** `/db/migrations` has no prod route today (test-only app in
    `MigrationsEndpointTest`); `/admin/maintenance/cleanup` lands with F-19. Allow-list entries
    are matched against the **full request path**, so `Definitions` prefixes them with
    `base_path` (Slim only strips it for route matching — otherwise static ops fallback would
    401 behind a reverse proxy).
  - **"static on migrations 204"** realized as `GET /admin/migrations/status` → 200; no 204
    endpoint exists in the admin surface.
  - Request enrichment: `admin_claims` / `admin_user` attributes are set on JWT auth (ready for
    later per-user admin auditing).
