# Repository + test duplication (Sonar "Duplicated Lines")

**Severity:** low — cosmetic quality-gate noise, no behavior risk. All other Sonar ratings are A.

SonarCloud flags duplicated blocks across repositories and integration tests:

| File | Dup lines | % |
|---|---|---|
| `src/Repositories/ClientRepository.php` | 58 | 33.0 |
| `src/Repositories/UserRepository.php` | 58 | 32.0 |
| `src/Repositories/LoginRepository.php` | 51 | 14.4 |
| `src/Repositories/OfflineSessionRepository.php` | 39 | 16.0 |
| `src/Repositories/SessionRepository.php` | 37 | 19.8 |
| `tests/Integration/SessionLoginManagementTest.php` | 115 | 28.6 |
| `tests/Integration/RateLimitingTest.php` | 43 | 15.0 |
| `tests/Integration/AdminCrudTest.php` | 42 | 8.0 |
| `tests/Integration/IntrospectionTest.php` | 26 | 11.7 |

(The controller-side duplication — `TokenController` / `IntrospectController` Basic-auth
block — is tracked separately in issue `05-basic-auth-parsing-duplication.md`; do not
duplicate it here.)

## What to fix

### Repositories

Two repeated idioms inside each repository class:

1. **fetch-one-row**: prepare → bind → execute → fetch → null-check → `buildFromData`
   → catch/rethrow `StorageFailed`. Repeated in e.g. `UserRepository::findById` vs
   `findByEmailAndRealmId`, `LoginRepository::findById` vs private `findBy`.
   Fix: one private `fetchOne(string $sql, array $params, string $errorContext): ?array`
   helper **per repository**.
2. **count**: `countByRealmId` / `countByClientId` / `countActiveByClientId` identical
   except SQL + error message. Fix: one private `count(string $sql, array $params): int`
   helper per repository.

Deliberately NOT in scope: a shared abstract base repository class. That trades
duplication for inheritance coupling across aggregates — keep helpers private and local.

### Tests

Repeated request/login/setup sequences in the four integration tests above.
Fix: extract shared helpers into `tests/Support/` (e.g. form-post and login-flow
helpers), following the existing `TestAppFactory` conventions.

## Acceptance criteria

- [ ] No repository contains two copies of the fetch-one-row or count idiom
- [ ] Sonar duplicated-lines % on all listed files below ~5% (or file no longer flagged)
- [ ] No shared base repository class introduced
- [ ] `composer test`, `composer check`, `composer test:e2e` all green

## Blocked by

None - can start immediately.
