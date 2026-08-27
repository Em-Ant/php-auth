# 03 — Migrate ops auth from api_key to offline token

- Interim: restrict `X-Admin-Key`/`Bearer api_key` to `POST /admin/migrations/*` and `POST /admin/maintenance/cleanup` (F-19). Return 401 elsewhere with `WWW-Authenticate` hint (align with F-43).
- Migrate: switch CI/deploy callers from `X-Admin-Key` to offline JWT — `ci-deployer` (confidential) + `scope=offline_access` → `offline_sessions` → `grant_type=refresh_token` (survives SSO logout, per `token-lifecycle #03`). Provide runbook + example `curl`/env wiring.
- End-state: remove `api_key` branch so Admin API accepts **JWT only** for ops — covers both SSO (UI, user-present) and offline (CI, headless) access tokens (both carry `admin` role, validated via `TokenValidator`, `iss` → `admin` realm). Keep `api_key` removal behind a flag/config until all callers migrated.
- Depends on F-19 endpoint shape; otherwise doc + removal patch.
