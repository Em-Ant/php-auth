# Wave 3 — LoginStateMachine consolidation + AuthOrchestrator split

Status: **DONE** 07/26/2026

## Problem

Two structural issues that don't need a full clean-architecture rewrite:

1. **LoginStateMachine re-fetched from DB** — The state machine called repo methods to persist, then re-fetched the entity via `findById` to return it. This meant the caller also called repo methods with the same data, creating a DRY violation where field logic lived in two places.

2. **AuthenticationOrchestrator god class** — 699 lines, 9 constructor dependencies, 16 methods covering login flow, token grants, revocation, and introspection. Adding or testing one concern required understanding all of them.

3. **InputValidator mixed responsibilities** — *(deferred)* Static utility class contains both domain validation and HTTP payload validation. No clear move without splitting.

## Changes

### Change 1 — Consolidate LoginStateMachine (validate + mutate + persist in one call)

The state machine kept its repo + logger dependencies but was simplified:

- Added 6 setters to `Login` entity: `setSessionId`, `setCode`, `setAuthenticatedAt`, `setRefreshToken`, `setUpdatedAt`, `setStatus`.
- Removed `findById` re-fetch — returns the mutated in-memory object instead.
- Removed repo failure `RuntimeException` throws *(re-added later per request)*.
- Removed `LoggerInterface` *(re-added later per request)*.
- Deleted `src/Interfaces/LoginStateMachine.php` (single concrete class, no interface needed).
- Each `doXxx()` method now: validates → mutates in-memory → persists → logs → returns the mutated object.
- Callers no longer call repo after the state machine — the state machine is the single point of contact.

### Change 2 — Split AuthenticationOrchestrator

Extracted three focused classes:

| New class                   | Extracted methods                                                                           | Dependencies (subset of original)                                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TokenGrantService`         | `getTokens`, `getTokensByCode`, `getTokensByRefreshToken`                                   | `SessionOrchestrator`, `IClientRepo`, `ISessionRepo`, `IUserRepo`, `ILoginRepo`, `LoginStateMachine`, `SecretsService`, `TokenService`, `LoggerInterface` |
| `TokenRevocationService`    | `revoke`, `validateClientSecret` (private)                                                  | `IClientRepo`, `ILoginRepo`, `LoginStateMachine`, `ISessionRepo`, `TokenService`, `TokenBlacklistRepository`, `SecretsService`, `LoggerInterface`         |
| `TokenIntrospectionService` | `introspect`, `validateIntrospectClient`, `introspectRefreshToken`, `introspectAccessToken` | `IClientRepo`, `ILoginRepo`, `TokenService`, `TokenBlacklistRepository`, `SecretsService`, `LoggerInterface`                                              |

**Stays on AuthenticationOrchestrator:** `validateRequiredLoginScope`, `initializeLogin`, `validateCsrfToken`, `createAuthorizedLogin`, `ensureValidCredentials`, `authenticateLogin`, `logout`, `getClientUri`, `parseValidToken`, `ensureValidClient`, `decodeTokenSafely`.

**`decodeTokenSafely`** is also needed by `TokenRevocationService` and `TokenIntrospectionService`. Duplicated as a private method on each (10 lines each, no state).

### Change 3 — InputValidator stays put

Deferred. Mixed domain/infra responsibility acknowledged; no correct move without splitting.

## Controllers updated

| Controller                | Old injection                | New injection               |
| ------------------------- | ---------------------------- | --------------------------- |
| `TokenController`         | `AuthenticationOrchestrator` | `TokenGrantService`         |
| `RevokeController`        | `AuthenticationOrchestrator` | `TokenRevocationService`    |
| `IntrospectController`    | `AuthenticationOrchestrator` | `TokenIntrospectionService` |
| `AuthorizationController` | `AuthenticationOrchestrator` | Unchanged                   |
| `LogoutController`        | `AuthenticationOrchestrator` | Unchanged                   |

## Tests

### LoginStateMachineTest

Still mocks `ILoginRepo` + `LoggerInterface`. Simplified:
- Removed `findById` mocks (no longer re-fetches)
- Removed `makeLogin` second instance for "updated" login
- Validates in-memory mutation directly (e.g., `getSessionId()`, `getRefreshToken()`)
- Kept repo failure tests (`RuntimeException` when repo returns false)

Before: 276 lines, 14 tests.
After: 244 lines, 18 tests (added 4 repo-failure back later, kept in-memory assertions).

### AuthenticationOrchestratorTest

Removed all token/revoke/introspect tests. Kept only login-flow + logout + getClientUri tests.
Integration tests (`FullFlowTest`, `TokenLifecycleTest`, `IntrospectionTest`) cover the HTTP-level flows.

## Risks

- **`decodeTokenSafely` duplication** — 3 copies of a 10-line private method. Acceptable for now.
- **`InputValidator` deferred** — The mixed responsibility is acknowledged. No issue for current scope.

## Completion checklist

Everything below was done in one or more passes between 07/25 and 07/26:

- [x] Problem identified and document written
- [x] Add 6 setters to `Login.php`
- [x] Consolidate `LoginStateMachine` — mutate in-memory before persist, return mutated object
- [x] Delete `src/Interfaces/LoginStateMachine.php`
- [x] Update callers — remove duplicate repo calls after state machine
- [x] Create `TokenGrantService` with `getTokens`, `getTokensByCode`, `getTokensByRefreshToken`
- [x] Create `TokenRevocationService` with `revoke`
- [x] Create `TokenIntrospectionService` with `introspect`
- [x] Update `TokenController` → `TokenGrantService`
- [x] Update `RevokeController` → `TokenRevocationService`
- [x] Update `IntrospectController` → `TokenIntrospectionService`
- [x] Update `config/di.php` — add 3 new services, remove `ILoginStateMachine` binding
- [x] Update `public/index.php` — inject new services in route closures
- [x] Update `AuthenticationOrchestratorTest` — remove token/revoke/introspect tests
- [x] Simplify `LoginStateMachineTest` — no `findById` mocks, test in-memory mutation
- [x] Run `composer test` — 237 tests pass
- [x] Run `composer stan` — level 5 passes
- [x] Run `composer cs_check` — PSR12 passes
