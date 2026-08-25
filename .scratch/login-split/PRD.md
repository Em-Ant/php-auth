# Login class split — lifecycle methods over raw setters

## Problem Statement

`AuthServer\Models\Login` trips Sonar `php:S1448` (24 methods > 20) and, more
substantively, is an anemic entity mutated through raw setters:

- All 6 setters (`setSessionId`, `setCode`, `setAuthenticatedAt`,
  `setRefreshToken`, `setUpdatedAt`, `setStatus`) are called exclusively by
  `LoginStateMachine` (17 call sites).
- Transitions are multi-step setter sequences (`setStatus(Active)` +
  `setRefreshToken()` + `setUpdatedAt()`), so nothing enforces valid states —
  e.g. `ACTIVE` without a refresh token is representable.
- Serialization knowledge is duplicated: `jsonSerialize()` (tested in
  `JsonSerializeTest`, excludes code/tokens) coexists with
  `LoginsController::toArray()` (different field set).

SOLID read: SRP strained (row mapping + lifecycle mutation + serialization);
ISP mildly violated (consumers see the whole surface); LSP/DIP fine.
The 16 getters are legitimate row-mapper accessors — the problem is the
mutation half, not the method count.

## Proposed Direction

1. **Intention-revealing transition methods on `Login`**, each stamping
   `updated_at` internally:
   - `markAuthenticated(string $sessionId, string $code)` (+ authenticated_at)
   - `markActive(string $refreshToken)`
   - `markRefreshed(string $refreshToken)`
   - `markExpired()`
   Raw setters become private or disappear. `LoginStateMachine` keeps policy
   (expiry math, persistence decisions) and calls these methods instead of
   poking fields — the machine orchestrates, the entity guards its invariants.
2. **One serialization home**: either drop `jsonSerialize()` as dead weight or
   make `LoginsController::toArray()` delegate to it — decide during
   implementation against the admin API contract (A-03 pagination envelope).
3. Explicitly **not** a `LoginRecord`/`LoginEntity` split: repositories
   hydrate via `buildFromData`; two types would double mapping code for no
   present gain.

## Out of Scope

- Silencing `php:S1448` — after the refactor ~16 getters + 4 transition
  methods likely still exceed 20; dismiss the rule instead if the count is
  deemed fine (it is a row-mapper, not a god class).
- Touching `OfflineSession`, which has its own (smaller) setter usage from
  `OfflineSessionService`.
- Changing login lifecycle semantics or persistence timing.

## Testing Decisions

- Existing `LoginStateMachineTest` must stay green unchanged (behavior
  preserved); add unit tests asserting each `mark*` produces the expected
  field combination (state + timestamps + tokens) — that is the new
  invariant home.
- Integration suite covers the flows end-to-end; no new integration tests
  needed.

## Size / Priority

P3, size S–M. Pure internal reshape behind a stable interface; best done when
login-lifecycle work is next touched (e.g. F-08/F-09 or F-39), not standalone.
