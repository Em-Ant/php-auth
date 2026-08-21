# Phase 2 — Client scopes + client roles

status: **DONE** — client-scope gating (2026-08-07); client roles (2026-08-21)

## Problem

Clients have no scope allow-list, so any client in a realm can request any
realm scope (e.g. `admin`). And only realm-wide roles exist — no per-client
authorization namespace.

## Changes

### 1. `clients.scope` column

Migration `NNN_client_scope.up.sql`:

```sql
ALTER TABLE clients ADD COLUMN scope varchar(100) DEFAULT NULL;
```

`NULL` = inherit `realms.scope`. Down: drop column.

- `Client` model + `ClientRepository` expose `getScope(): ?array`.

### 2. Client role axis

Two options (decision needed at implementation):

- **Target (normalized, Keycloak-style)**:
  `roles(id, realm_id, client_id NULL, name, description)` + `user_role_assignments(user_id, role_id)`.
  `client_id IS NULL` ⇒ realm role. Migrates `users.realm_roles` into assignments.
- **Pragmatic**: keep `users.realm_roles`, add `users.client_roles` as a JSON
  column `{ "client_name": ["role", ...] }`. Less schema churn, denormalized.

### 3. `ScopeResolver` service

Single place for the scope intersection, replacing the 3 duplicated checks:

```php
resolve(?string $requested, Client $client, Realm $realm, bool $requireOpenid): string
// granted = requested ∩ client.scope(?realm) ∩ realm.scope
```

- auth_code: `requireOpenid=true`
- client_credentials: `requireOpenid=false`, `requested` omitted → client scope
  (or realm scope)
- Wire into `config/di.php`; call from `AuthenticationOrchestrator`
  (`validateRequiredLoginScope`, `createAuthorizedLogin`) and
  `TokenGrantService::getClientCredentialsTokens`. Remove the old checks.

### 4. Claims

- Access token: add `resource_access.<client>.roles` when client roles exist.
- Refresh token: same namespaces as today (`realm_access.roles` already present).
- Introspection: expose `resource_access` (RFC 7662 allows arbitrary claims).

## Touch points

- Migrations + `db/seed.sql` (client scope values for seeded clients)
- `Client`, `User` models + repositories
- `ScopeResolver` (new), `AuthenticationOrchestrator`, `TokenGrantService`,
  `TokenService`, `TokenIntrospectionService`, `config/di.php`
- Tests: unit (`ScopeResolverTest`, `InputValidatorTest`) + integration
  (client-scope denial in auth-code and client_credentials flows)

## Acceptance

- A client requesting a scope not in its `clients.scope` → rejected with
  `invalid scope`, even if the realm allows it.
- Seeded clients keep working (scope NULL → inherit realm, defaults unchanged).
- All existing tests + `composer check` stay green.

## Comments

### 2026-08-07 — Client-scope gating shipped; client roles split out

Decided to deliver only the **client-scope gating** half of this issue first (it
unblocks `offline_access` per-client gating for token-lifecycle #03). The client
role axis (sections 2 + 4 below) is deferred to a dedicated follow-up issue —
the roadmap item was split accordingly.

Implementation notes:

- Migration `003_client_scope` adds `clients.scope varchar(100) DEFAULT NULL`
  (`NULL` = inherit `realms.scope`).
- New `AuthServer\Services\ScopeResolver` centralizes the check; the 4
  duplicated validations were removed (`validateRequiredLoginScope`,
  `createAuthorizedLogin`, `authenticateLogin`, `getClientCredentialsTokens`).
  `InputValidator::validateScope` was deleted.
- **Semantics: strict rejection** (`invalid scope`), not PRD narrowing — a
  requested scope must be in both the client's effective allow-list and the
  realm's. This matches the issue's Acceptance criteria and preserves the
  existing `invalid scope` behaviour for `client_credentials`.
- `openid` is **implicitly always allowed** even if omitted from
  `clients.scope` (Keycloak parity: it is a built-in scope every client has).
  `requireOpenid=true` still rejects a request without `openid` in the
  auth-code flow.
- `client_credentials` with an omitted `scope` now grants the client's
  _effective_ allow-list (was: realm scope).
- `db/seed.sql` unchanged — seeded clients keep `scope NULL` (inherit).
- Tests: `ScopeResolverTest` (unit) + `ClientScopeTest` (integration,
  auth-code + client_credentials + `offline_access` gating). 267 tests green;
  `composer check` clean.

Outstanding for the follow-up: client role storage decision (normalized `roles`
table vs pragmatic `users.client_roles` JSON), `resource_access.<client>.roles`
claims, and introspection passthrough.

### 2026-08-21 — Client roles shipped

Chose the **normalized** option: `roles(id, realm_id, client_id NULL, name)`

- `user_role_assignments(user_id, role_id)`.

* Migration `005_roles` creates both tables and migrates the legacy
  space-separated `users.realm_roles` column via recursive-CTE split, then
  drops it. Every realm role is also **mirrored as a client role on each
  client of the realm** with matching assignments — preserving the
  pre-migration behaviour where clients inherited the whole realm-role
  namespace. Down migration folds assignments back into `realm_roles`.
* `RoleRepository` + interface; `UserRepository::buildFromData` hydrates realm
  - client roles through it. `User` carries `clientRoles`
    (`array<string, list<string>>`) instead of a raw string.
* Claims: access + refresh tokens emit `resource_access.<client>.roles`
  (only the requesting client, only roles the user holds);
  introspection passes `resource_access`/`realm_access` through.
* `syncRealmRoles` upserts missing realm roles; client assignments untouched.
  No write path for client roles yet — admin CRUD is F-12 (issue 04),
  scope↔role mapping is F-05 (issue 03).
* Tests: `RolesMigrationTest` (migration data path), `RoleRepositoryTest`,
  `TokenServiceTest` resource_access cases; e2e step 3c verifies the claim on
  access/refresh tokens + introspection passthrough. 477 tests green;
  `composer check` clean; e2e 153/153.
