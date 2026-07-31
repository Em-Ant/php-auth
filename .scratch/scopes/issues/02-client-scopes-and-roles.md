# Phase 2 — Client scopes + client roles

status: **TODO** (second step of `.scratch/scopes/PRD.md`)

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
