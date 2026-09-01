# Admin Controller Refactor — Extract Application Services

## Problem Statement

The OIDC protocol controllers (`AuthorizationController`, `TokenController`, `IntrospectController`, `RevokeController`, `LogoutController`) are properly thin adapters that delegate all orchestration to application services. The admin controllers do not follow this pattern — 6 of 11 directly access repositories and contain business logic that belongs in the application layer.

### Fat controllers

| Controller | Lines | Repos | Business Logic |
|---|---|---|---|
| `ClientsController` | 260 | 4 | Invariant checks (public/secret), cascading delete orchestration, duplicate detection, secret hashing |
| `UsersController` | 237 | 5 | Duplicate email detection, password validation, role parsing, cascading delete checks |
| `RealmsController` | 190 | 3 | Duplicate name detection, key existence validation, cascading delete checks |
| `RolesController` | 173 | 3 | In-memory duplicate detection, FK validation before create |
| `ScopeRolesController` | 164 | 3 | Scope validation against realm config, duplicate detection |
| `OidcController` | 123 | 1 | `sendUserInfo()` scope-to-claims mapping, name splitting |

### Lean controllers (already correct — no changes needed)

`SessionsController`, `LoginsController`, `OfflineSessionsController`, `MigrationsController`, `KeysController`, `UserRolesController`, `ErrorController`.

## Goal

Make every admin controller a thin adapter: parse input, call one service method, map the result to a response. All orchestration and business rules live in application services.

The existing admin services (`UserAdminService`, `RoleAdminService`, `SessionRevocationService`) already demonstrate the target pattern. This refactor extends it to the remaining fat controllers.

## Approach: Single-Pass Refactor

One session (or two if too large), not a series of small PRs. Each controller gets refactored end-to-end: extract service, rewire DI, update tests, verify with `composer check`.

## Scope

### New application services

1. **`ClientAdminService`** — extracted from `ClientsController`
   - `create(array $params, string $realmId): Client` — realm lookup, duplicate name check, invariant enforcement (public no secret, confidential requires secret), secret hashing, persist
   - `update(Client $existing, array $params): Client` — same invariants, secret hashing if changed, persist
   - `delete(string $clientId): void` — cascade guard: check active logins + offline sessions, delete offline sessions, delete client
   - Deps: `ClientRepository`, `RealmRepository`, `LoginRepository`, `OfflineSessionRepository`, `SecretsService`

2. **`RealmAdminService`** — extracted from `RealmsController`
   - `create(array $params): Realm` — duplicate name check, key existence validation, persist
   - `update(Realm $existing, array $params): Realm` — same checks, persist
   - `delete(string $realmId): void` — cascade guard: check client + user count, refuse if non-zero
   - Deps: `RealmRepository`, `ClientRepository`, `UserRepository`, `KeyStore`

3. **`ScopeRoleAdminService`** — extracted from `ScopeRolesController`
   - `create(string $clientId, string $scope, string $roleId): ScopeRoleMapping` — client existence, scope validation against realm, duplicate check, persist
   - `update(string $mappingId, string $scope, string $roleId): ScopeRoleMapping` — scope validation, persist
   - `delete(string $mappingId): void` — persist
   - Deps: `ClientRepository`, `RoleRepository`, `RealmRepository`

4. **`UserInfoService`** (or extend `AuthenticationOrchestrator`) — extracted from `OidcController::sendUserInfo()`
   - `getUserInfo(string $userId, string $scope): array` — user lookup, scope-to-claims mapping, name splitting
   - Deps: `UserRepository`

5. Extend **`RoleAdminService`** — already exists for delete; add `create()` and `update()` with duplicate detection and FK validation (currently in `RolesController`). Also migrate it to use the `RunsTransactions` trait for consistency with `UserAdminService` and `SessionRevocationService` (currently manages transactions inline).

### Controllers to thin

After extraction, each controller should:
- Inject **one** application service (plus input helpers as needed)
- Parse request input (path params, query params, body)
- Call service method(s)
- Map result to `JsonResponse`
- Handle exceptions

| Controller | Current deps | Target deps |
|---|---|---|
| `ClientsController` | 4 repos + SecretsService | `ClientAdminService` |
| `UsersController` | 5 repos + SecretsService + UserAdminService + RoleRepository | `UserAdminService` (extended) + `RoleRepository` for list/assign only |
| `RealmsController` | 3 repos + KeyStore | `RealmAdminService` |
| `RolesController` | 3 repos + RoleAdminService | `RoleAdminService` (extended) |
| `ScopeRolesController` | 3 repos | `ScopeRoleAdminService` |
| `OidcController` | 1 repo + KeyStore + issuer | `UserInfoService` + KeyStore + issuer |

### What stays in controllers

- Input parsing (`requiredString`, `optionalString`, `paginationFromQuery`)
- Existence checks for list/read endpoints (thin CRUD — one repo call, map to response)
- Exception-to-JSON mapping

## Out of Scope

- Domain model changes (anemic domain stays)
- Repository interface changes
- Non-admin controllers (already lean)
-`\JsonSerializable` on models (low impact, high churn)

## Testing

- Existing integration tests exercise all admin CRUD paths — they should pass after refactor with minimal changes (only constructor args change)
- No new test files needed — the behavior is identical, just moved between layers
- Run `composer check` (PHPStan + PHPCS) after each controller extraction

## Verification

1. `composer test` — all existing tests pass
2. `composer stan` — no new PHPStan errors
3. `composer cs_check` — PSR12 compliance
4. Manual review: every controller method is ≤ 15 lines, injects at most one service + input helpers

## Issues

- [#01](issues/01-extract-admin-services.md) — single-pass implementation (**done 09/01/2026, R-15**)
