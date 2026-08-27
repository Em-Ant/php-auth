# 02 — JWT admin auth middleware (dual-mode)

- New `AdminAuthMiddleware` (or rename `AdminMiddleware`): try JWT via `TokenValidator` (`issuer`, `exp`, `iss` → admin realm, `realm_access.roles` contains `admin`), then fallback to `hash_equals(api_key)` only on allow-listed ops paths. **Accept both SSO and offline access tokens** identically (no `typ` check; `offline_sessions` TTL already enforced at mint/refresh; `TokenValidator` covers both).
- Wire in `src/App/AppBuilder.php:295 registerAdminRoutes()` + `src/Config/Definitions.php:88`; keep `X-Admin-Key`/`Bearer api_key` compat outside allow-list → 401.
- Explicitly allow `admin-ui` PKCE access token to call `POST /admin/migrations/*` + `POST /admin/maintenance/cleanup` (F-19) — user-present ops need no offline token.
- Tests: unit (token valid/invalid/expired/wrong realm/missing role, SSO vs offline both pass/fail on role) + integration (admin JWT succeeds, non-admin JWT 401, static on non-ops 401, static on migrations 204).
- Must pass `composer check` (PHPStan 5, PSR12).
