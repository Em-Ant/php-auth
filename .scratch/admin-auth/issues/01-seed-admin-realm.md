# 01 — Seed admin realm, role, and clients

status: **DONE** 2026-08-28 (F-47) — uncommitted working tree (`db/seed.sql`, `bin/seed`,
`bin/seed-keys.php`, `composer.json`; 584 tests / 1705 assertions OK, `composer check`
clean). Prod bootstrap is not covered by dev seed — see
[admin-auth/release-plan.md](../release-plan.md).

- Seed `admin` realm (`realms` row, `keys_id` via existing `POST /admin/keys` flow or pre-generated kid), role `admin` (`roles` table, `client_id NULL`), clients:
  - `admin-ui` — public PKCE, `authorization_code`, `clients.scope="openid profile email"` (**no** `offline_access` by default; SSO sessions only; UI runs migrations with short-lived access token).
  - `ci-deployer` — confidential, `clients.scope` includes `offline_access` (realm `realms.scope` must also include it) → mints `offline_sessions`.
- Realm `realms.scope` must include `offline_access` so per-client gating (`ScopeResolver`, `scopes #02`) can allow it for `ci-deployer` only. Document that `admin` realm supports **both SSO and offline** like any realm (no special flag).
- Extend `db/seed.sql` (dev-only, idempotent `WHERE realm_id IS ...` guards per AGENTS.md Sonar rule) + `bin/seed`.
- Verify well-known + OIDC auth/token round-trip for `admin` realm via integration test (SSO + offline grant for `ci-deployer`).
