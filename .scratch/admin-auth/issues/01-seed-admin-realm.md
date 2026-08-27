# 01 — Seed admin realm, role, and clients

- Seed `admin` realm (`realms` row, `keys_id` via existing `POST /admin/keys` flow or pre-generated kid), role `admin` (`roles` table, `client_id NULL`), clients:
  - `admin-ui` — public PKCE, `authorization_code`, `clients.scope="openid profile email"` (**no** `offline_access` by default; SSO sessions only; UI runs migrations with short-lived access token).
  - `ci-deployer` — confidential, `clients.scope` includes `offline_access` (realm `realms.scope` must also include it) → mints `offline_sessions`.
- Realm `realms.scope` must include `offline_access` so per-client gating (`ScopeResolver`, `scopes #02`) can allow it for `ci-deployer` only. Document that `admin` realm supports **both SSO and offline** like any realm (no special flag).
- Extend `db/seed.sql` (dev-only, idempotent `WHERE realm_id IS ...` guards per AGENTS.md Sonar rule) + `bin/seed`.
- Verify well-known + OIDC auth/token round-trip for `admin` realm via integration test (SSO + offline grant for `ci-deployer`).
