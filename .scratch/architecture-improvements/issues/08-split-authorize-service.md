# Split AuthorizeService into InputValidator + SessionOrchestrator + AuthenticationOrchestrator

**Issue**: 08  
**PRD**: Wave 2  
**Risk**: High (touches the auth flow core; all existing integration tests exercise this path)  
**Dependencies**: Issue 07 (container kernel makes wiring the new classes trivial)  
**Branch naming**: `refactor/split-authorize-service`

## Work

### Step 1 — Create `src/Services/InputValidator.php`

Extract these private static methods from `AuthorizeService`:

- `validateScope(string $scope, string $allowed): void`
- `validateRedirectUri(string $uri, string $clientUri): void`
- `validateCsrfToken(string $token, string $expected): void`
- `strStartsWith(string $haystack, string $needle): bool` — rename to `startsWith` or inline since PHP 8 has `str_starts_with()`
- `isEmpty($value): bool`

Also move `validateQueryParams`, `validateTokenParams`, `validateParams` from `AuthorizeService` — these assemble and call the above validators.

All methods are **public static pure functions** — zero dependencies, no side effects, no mocks needed in tests.

### Step 2 — Create `src/Services/SessionOrchestrator.php`

Extract session lifecycle from `AuthorizeService`:

- `ensureValidSession(Realm $realm, User $user): Session` — creates or reuses a session
- `checkExpiry(Session $session): bool` — pure check, no mutation (CQS fix)
- `expire(Session $session): void` — explicit mutation

Depends on `SessionRepository` only.

### Step 3 — Create `src/Services/AuthenticationOrchestrator.php`

The remainder of `AuthorizeService` after extracting validation and session management:

- `initializeLogin(Realm, Client, array $params): Login`
- `authenticateLogin(Login, string $password): void`
- `getTokensByCode(Login): array`
- `getTokensByRefreshToken(string $token, Realm, Client): array`
- `logout(Login, ?Session): void`
- `parseValidToken(string $token, Realm): array`

Depends on `InputValidator`, `SessionOrchestrator`, `LoginStateMachine`, `TokenService`, `SecretsService`, and all 5 repositories.

### Step 4 — Replace domain exceptions

Delete `src/Exceptions/InvalidInputException.php` (400), `StorageErrorException.php` (500), `CriticalLoginErrorException.php` (400).

Create:
- `src/Exceptions/ValidationFailed.php` extends `\InvalidArgumentException`
- `src/Exceptions/AuthenticationFailed.php` extends `\RuntimeException`
- `src/Exceptions/StorageFailed.php` extends `\RuntimeException`

No HTTP status codes in these classes. The controller (`Authorize.php`) catches them and maps to HTTP responses.

### Step 5 — Update `AuthorizeController`

The controller currently catches `InvalidInputException` (code → 400), `StorageErrorException` (code → 500), `CriticalLoginErrorException` (code → 400). Update catches to the new exception types and map explicitly:

```php
catch (ValidationFailed | AuthenticationFailed $e) { return JsonResponse::error($response, ..., 400); }
catch (StorageFailed $e) { return JsonResponse::error($response, ..., 500); }
```

### Step 6 — Wire in container

Register `InputValidator`, `SessionOrchestrator`, `AuthenticationOrchestrator` in `config/di.php`. The controller depends on `AuthenticationOrchestrator` instead of `AuthorizeService`. The old `AuthorizeService` class is deleted.

### Step 7 — Update `index.php` route wiring

The controller constructor changes — it takes `AuthenticationOrchestrator` instead of `AuthorizeService`. Update the instantiation (or if Issue 07 is done, the container wires it automatically).

### Step 8 — Update tests

- `InputValidatorTest` — pure function tests, zero mocks
- `SessionOrchestratorTest` — mock `SessionRepository`
- `AuthenticationOrchestratorTest` — mock its 3+ dependencies
- `FullFlowTest` — should pass unchanged (same behaviour, different class names)

## Verification

- [ ] All existing integration tests pass (the auth flow behaviour is unchanged)
- [ ] `InputValidator` has unit tests with no mocks
- [ ] `SessionOrchestrator::checkExpiry()` returns bool and does NOT call `setExpired()`
- [ ] No exception class contains a hardcoded HTTP status code
- [ ] `phpstan analyse -l 5` passes
- [ ] `phpcs src --standard=PSR12` passes
