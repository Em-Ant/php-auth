# F-50 — Admin credential rotation via existing PUT APIs (no new endpoints)

**Status: implemented.** Decision record for the pivot away from the PRD's
dedicated endpoints (see `../PRD.md ## Comments`).

## Why no new endpoints

`PUT /admin/users/{id}` already accepts `password` (hashed server-side via
`SecretsService`, no current password required) and `PUT /admin/clients/{id}`
already accepts `client_secret`. The PRD's "no way to rotate without
delete/recreate" was stale. Dedicated action endpoints would duplicate the
mutation path (DRY violation) for no capability gain; the actual gaps were
session revocation, the client/secret invariant, and documentation.

## What shipped

| Change | Where |
|---|---|
| Password rotation revokes sessions + offline grants atomically (fires whenever a password value is submitted; omitting `password` keeps everything) | `src/Services/UserAdminService.php` (`rotatePassword`), `src/Controllers/Admin/UsersController.php` |
| Revocation logic extracted to a single home (`revokeFor(?userId, ?clientId)`, `revokeSession(id)`) | `src/Services/SessionRevocationService.php`, used by `SessionsController` and `UserAdminService` |
| Client invariant: confidential ⇒ has secret, public ⇒ no secret; promotion requires secret in the same call; demotion auto-clears the secret (409 otherwise); strict boolean parsing for `require_auth` | `src/Controllers/Admin/ClientsController.php` (create + update) |
| Fail-closed on confidential client with no stored hash (was TypeError → 500 on legacy rows) | `src/Services/ClientAuthenticator.php` |

## Design notes

- Rotation is atomic: `UserAdminService::rotatePassword()` wraps the user
  update, role sync and revocation in one transaction. A failed revocation
  rolls the whole rotation back — all-or-nothing, safe to retry. (An earlier
  revision ran the revoke after the update and accepted a partial-failure
  state; the review pass replaced it with the transactional design.)
- Trigger semantics: submitting a `password` value counts as a rotation even
  if the plaintext equals the old password (salted hashes make same-value
  detection possible via `validatePassword`, but a "rotation" that silently
  logs nobody out is more surprising than the logout). Omitting the key keeps
  sessions untouched.
- Strict booleans for `require_auth`: garbage values (e.g. `"treu"`) are
  rejected with 400 instead of being coerced to false — coercion would hit
  the demotion branch and destroy the stored secret.
- Invariant checks run before any hashing: rejected requests cost no argon2
  work and empty-string secrets on public clients surface as 409, not 400.
- `null` and the legacy empty-string hash are both "no secret" in the
  invariant, so a broken legacy row cannot be promoted without a real secret.
- Demotion auto-clear (vs reject) chosen so the "public ⇒ no secret" invariant
  never blocks a demotion and no dead secret survives; a secret provided in
  the same demotion request is rejected as contradictory input.
- 409 (ConflictException) for all invariant violations, matching the existing
  admin-API conflict convention.

## Verification

- `composer test` — 631 tests green, including: password change revokes
  sessions/logins/offline grants, unchanged-password PUT keeps sessions,
  secret rotation via PUT, promotion/demotion/invariant branches, and the
  legacy broken-row token-endpoint test (401, not 500).
- `composer stan` / `composer cs_check` clean; sonar-php heuristic scan +
  duplication gate on the diff clean (manually confirmed: S2761 false positive
  on `$count++`, S2068 on test fixture literals).
- E2E (`bin/e2e-test.sh`) unaffected: it never authenticates the client whose
  secret step 17's demotion clears.
