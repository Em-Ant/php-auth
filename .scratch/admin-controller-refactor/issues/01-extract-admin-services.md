# 01 — Extract Admin Application Services (Single-Pass Refactor)

status: **DONE** 09/01/2026 (R-15)

## Summary

Thin all fat admin controllers by extracting business logic into application services. One pass, end-to-end.

## Steps

### 1. ClientAdminService

Create `src/Services/ClientAdminService.php`:
- `create(array $params, string $realmId): Client`
- `update(Client $existing, array $params): Client`
- `delete(string $clientId): void`

Rewire `ClientsController` to inject `ClientAdminService` instead of 4 repos + SecretsService. Controller keeps: `list()`, `read()` (thin CRUD), plus `create()`, `update()`, `delete()` now delegating to service.

Move from controller to service:
- `assertPublicHasNoSecret()` / `assertConfidentialHasSecret()` — invariant checks
- `findDuplicate()` — duplicate name detection
- `optionalSecret()` / `hashSecret()` — secret hashing
- `delete()` cascade logic — check logins, offline sessions, delete offline sessions, delete client
- Entity construction in `create()` / `update()`

### 2. RealmAdminService

Create `src/Services/RealmAdminService.php`:
- `create(array $params): Realm`
- `update(Realm $existing, array $params): Realm`
- `delete(string $realmId): void`

Rewire `RealmsController` to inject `RealmAdminService` instead of 3 repos + KeyStore. Controller keeps: `list()`, `read()`.

Move from controller to service:
- Duplicate name detection
- `assertKeysExist()` — key store validation
- `delete()` cascade guard — client + user count checks

### 3. Extend RoleAdminService

Extend `src/Services/RoleAdminService.php` with:
- `create(string $realmId, ?string $clientId, array $params): Role`
- `update(Role $existing, array $params): Role`

Note: `RunsTransactions` trait already applied and `deleteRole()` already uses it. Only the new methods are needed.

Rewire `RolesController` to inject `RoleAdminService` (already partially done for delete). Remove `RoleRepository`, `RealmRepository`, `ClientRepository` from controller constructor.

Move from controller to service:
- `findDuplicate()` — currently loads all roles and iterates in PHP
- Realm/client FK validation before create
- Entity construction

### 4. ScopeRoleAdminService

Create `src/Services/ScopeRoleAdminService.php`:
- `create(string $clientId, array $params, string $scope, string $roleId): ScopeRoleMapping`
- `update(string $mappingId, string $scope, string $roleId): ScopeRoleMapping`
- `delete(string $mappingId): void`

Rewire `ScopeRolesController` to inject `ScopeRoleAdminService` instead of 3 repos. Controller keeps: `list()` (thin CRUD with in-memory pagination).

Move from controller to service:
- `assertScopeIsValidForClient()` — scope validation against realm config
- Duplicate detection before create
- Entity construction

### 5. UserInfoService

Create `src/Services/UserInfoService.php`:
- `getUserInfo(string $userId, string $scope): array`

Rewire `OidcController` to inject `UserInfoService` instead of `UserRepository`.

Move from controller to service:
- `sendUserInfo()` body — user lookup, scope→claims mapping, `splitName()` logic

### 6. Thin UsersController

`UsersController` currently has 5 repos + 2 services. After steps above, re-evaluate what can be removed:
- Duplicate email detection → move to `UserAdminService` (new method or extend `createUser`)
- Password validation → already in `SecretsService`, just needs orchestration in `UserAdminService`
- `delete()` cascade logic → move to `UserAdminService::deleteUser()`
- Role parsing (`splitRoles`) → move to `UserAdminService` or keep as static helper in controller (input parsing)

Target: `UserAdminService` + `RoleRepository` (for role listing/assignment only) + `SessionRepository` (for list only).

### 7. Register new services in Definitions

Add to `src/Config/Definitions.php`:
- `ClientAdminService::class`
- `RealmAdminService::class`
- `ScopeRoleAdminService::class`
- `UserInfoService::class`

### 8. Verify

- `composer test` — all tests pass
- `composer stan` — no new errors
- `composer cs_check` — PSR12 clean
- Review each controller: ≤ 15 lines per method, one service + input helpers

## Estimated size

M (single session). The changes are mechanical — extract, rewire, verify. No domain model changes.

## Verification (09/01/2026)

- `composer test` — 656 tests / 1866 assertions OK (was 645; new service-level tests added)
- `composer stan` — level 5, no errors
- `composer cs_check` — PSR12 clean
- `composer test:e2e` — 252 passed / 0 failed
- Sonar scan (`scan.php.py --diff-ref=HEAD --fail-on-dup=3.0`) — no findings, dup gate OK
- Every fat controller now injects at most one application service + repos for thin CRUD reads
