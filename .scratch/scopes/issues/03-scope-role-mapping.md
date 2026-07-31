# Phase 3 — Scope↔role mapping (joining config, full Keycloak style)

status: **TODO** (final step of `.scratch/scopes/PRD.md`)

## Problem

Even after Phase 2, scope and roles are independent: a token can carry `admin`
scope for a user who is not an admin, because nothing links "scope X requires
role Y". In Keycloak this linkage is the **role scope mapping** on a client
scope.

## Model

A client scope can carry two kinds of role mappings, evaluated at **issuance**:

1. **Roles to include** — when the scope is granted, these roles are emitted in
   the token, but **only if the user actually has them**.
2. **Roles required** — if the user lacks a required role, the scope itself is
   dropped from the granted scope (issuance-time gate).

Resolution at token-issue time (Keycloak-style):

```
granted_scope = requested ∩ realm.scope ∩ client.scope
  − scopes whose required roles the user lacks

included_roles = { roles mapped to granted scopes ∪ client role mappings }
  ∩ user's actual roles

realm_access.roles        = included realm roles
resource_access.<c>.roles = included client roles for this client
```

## Schema

```sql
CREATE TABLE client_scope_roles (
  client_id  varchar(36) NOT NULL,
  scope      varchar(100) NOT NULL,
  role_id    varchar(36) NOT NULL,   -- references roles(id)
  required   boolean DEFAULT 0,      -- 1 = scope dropped if user lacks this role
  PRIMARY KEY (client_id, scope, role_id)
);
```

Assumes Phase 2's normalized `roles` + `user_role_assignments` tables.

## Changes

- `ScopeResolver`/`TokenService` evaluate the mapping during bundle creation
  (auth_code flow; client_credentials has no user so `required` is moot).
- Role claim filtering: never emit a role the user doesn't hold.
- Admin surface to manage mappings (ties into the roadmap **Admin API** work):
  assign role scope mappings per client, mark `required`.
- Well-known stays config-derived (Phase 1); no new discovery fields needed.

## Later refinement (explicitly deferred)

- **Composite roles** (role → role inclusion), Keycloak's `composite` flag.
- Scope↔role mappings for `client_credentials` via service-account users.

## Touch points

- Migration `client_scope_roles`
- `ScopeResolver` (mapping lookup + role filtering), `TokenService` (claims),
  `AuthenticationOrchestrator`
- Admin API CRUD for mappings
- Tests: unit (resolver mapping logic) + integration (non-admin with `admin`
  scope gets it dropped; mapped roles appear only when user holds them)

## Acceptance

- Non-admin user requesting `admin` scope → scope dropped at issuance (token
  carries no `admin` scope).
- Admin user requesting `admin` scope → `realm_access.roles` includes `admin`.
- A client role mapped to a granted scope appears in
  `resource_access.<client>.roles` only if the user has it.
- All existing tests + `composer check` stay green.
