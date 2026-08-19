# CI E2E — two scopes, one canonical flow

## Problem Statement

The repo has two E2E shell scripts:

- `bin/e2e-test.sh` — local OIDC behavioral-integrity suite (`composer test:e2e`).
  DB access (dev-server harness, `sqlite3` leftover checks), admin-API CRUD to
  build a disposable realm, 146 checks.
- `bin/e2e-test-keycloak.sh` — post-deploy smoke test (`composer test:e2e:kc`,
  GitHub Actions deploy pipeline). **No DB access, no admin API, bounded
  footprint** — but drifts from the local suite.

The original "merge the two scripts" premise was **wrong**: the two targets have
opposite constraints (local = heavy regression w/ DB; prod = zero-DB, minimal
pollution). Merging would leak prod-polluting steps into prod or strip
prod-safe coverage locally.

## Goal (revised)

Split deliberately into two artifacts with distinct contracts, not one merged
script:

1. **`bin/smoke-test.sh`** (rename/repurpose of `e2e-test-keycloak.sh`) — the
   prod post-release smoke. Invariants: **no DB access, no admin API, bounded
   footprint** (one login; refresh + access revoked at the end; never creates
   realms/clients/users/keys). ~30 checks: discovery, `/certs`,
   auth→login→token, introspect, userinfo, refresh, revoke, prompt=none,
   logout. Config via `BASE_URL`/`REALM`/`CLIENT`/`REDIRECT_URI` env.
   Composer: `test:smoke`.
2. **`bin/e2e-test.sh`** — stays the local OIDC integrity suite (dev-server
   harness, DB-backed verification, all 146 checks). The admin-CRUD stage is
   reframed as harness (builds a disposable realm for the OIDC flow), not OIDC
   scope.

## Phase 2 (better than bash; no Playwright/browser)

A **PHPUnit suite that drives a live `BASE_URL` over HTTP** (PSR-18/curl):
real JSON parsing + structured asserts instead of `grep`/`sed`. The *same*
test files run against local dev server and prod; the prod subset is gated by
env or a dedicated smoke group. PHP + PHPUnit are already dependencies. Bash
remains the phase-1 source of truth.

Status: **OPEN** — F-20 reframed from "merge" to "split + define contracts".
