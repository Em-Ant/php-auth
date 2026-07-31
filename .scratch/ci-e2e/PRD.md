# CI E2E — deduplicate e2e scripts

## Problem Statement

The repo has two near-identical E2E shell scripts:

- `bin/e2e-test.sh` — local dev-server smoke test (`composer test:e2e`)
- `bin/e2e-test-keycloak.sh` — post-deploy smoke test in the GitHub Actions
  pipeline (`composer test:e2e:kc`, invoked by `.github/workflows/deploy.yml`)

They share ~95% of the flow (auth → login → token → introspect → refresh →
revoke → client_credentials) but drift independently: step numbering has
already diverged, and features added to one script are not automatically added
to the other (the local script gained the client_credentials step before the
keycloak script did).

## Goal

One canonical E2E script that covers both targets. Making it configurable via
env vars removes the need for two copies.

Status: **DEFERRED** — the two scripts were only aligned feature-wise for now
(see issue 01). No pipeline/config changes were made.

## Issues

- [#01](issues/01-merge-scripts.md) — Merge the two E2E scripts into one configurable script
