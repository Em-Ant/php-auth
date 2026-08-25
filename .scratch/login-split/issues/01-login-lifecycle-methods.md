# 01 — Login lifecycle methods + single serialization home

Parent: `.scratch/login-split/PRD.md`
Type: refactor · Priority: P3 · Size: S–M

## Goal

Replace `Login`'s six raw setters with intention-revealing transition methods
and collapse the duplicated serialization.

## Tasks

- [ ] Add `markAuthenticated(sessionId, code)`, `markActive(refreshToken)`,
      `markRefreshed(refreshToken)`, `markExpired()` on `Login`; each sets
      `updated_at` internally and asserts its own preconditions (e.g. active
      requires a non-empty refresh token).
- [ ] Demote/remove the six public setters.
- [ ] Rewire `LoginStateMachine` (`doAuthenticate`, `doActivate`, `doRefresh`,
      `doExpire`, `doCheckExpiry`) to the new methods — policy and persistence
      stay in the machine.
- [ ] Serialization: pick one home (`jsonSerialize()` vs
      `LoginsController::toArray()`); delete or delegate the other. Verify
      against `JsonSerializeTest` expectations (code/csrf/refresh_token
      excluded where applicable) and the A-03 response envelope.
- [ ] Update `tests/Unit/Models/JsonSerializeTest.php` and any direct setter
      usages in tests to the new API.

## Acceptance

- No code outside `Login` mutates login fields directly (grep for
  `->set(Status|Code|SessionId|AuthenticatedAt|UpdatedAt|RefreshToken)` on
  `Login` returns nothing).
- `composer check` clean, full PHPUnit suite green, e2e smoke green.
- Invalid transitions unrepresentable: unit test proves `markActive('')`
  (or equivalent misuse) throws.

## Notes

Sonar `php:S1448` will likely still fire (~21 methods). Dismiss with comment
"row-mapper accessors" rather than contorting the class to satisfy the count.
