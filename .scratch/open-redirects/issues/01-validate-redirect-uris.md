# 01 — Validate redirect_uri in `prompt=none` and logout

**Status:** done
**Depends on:** PRD.md (behavior spec + acceptance criteria)

## Task

Close the two open-redirect holes and the adjacent param-validation defects,
per `PRD.md`:

1. `authorize`: run `InputValidator::validateQueryParams` first; validate
   `redirect_uri` in the `prompt=none` error branch (no redirect to unregistered
   URIs; render `/error` page instead).
2. `logout`: resolve client from id_token (`azp` → `aud`), validate
   `post_logout_redirect_uri`; drop `Location` when unvalidated.
3. Expose a public redirect-validation entry point on
   `AuthenticationOrchestrator` (currently `ensureValidClient` is private).

## Acceptance

Eight integration tests listed in PRD acceptance criteria. `composer check`
clean, full suite green, E2E 30/30.

## Comments

2026-08-09 — Implemented. All PRD acceptance criteria pass: 303 PHPUnit tests
green (14 new unit + 8 new integration, incl. the `prompt=none` with/without
session, missing-param 400s, and logout positive/negative/subpath cases),
`composer check` clean, local E2E 36/36. E2E scripts gained `prompt=none`
(no-session) and logout redirect-validation steps (local + production);
the silent-auth (cookie) branch is covered by the PHPUnit integration test.
