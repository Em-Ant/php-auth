# Phase 3 — Scope↔role mapping (joining config, full Keycloak style)

status: **DONE** (2026-08-26)

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

## Implementation notes (2026-08-26)

### Keycloak parity decision

Keycloak's "Full Scope Allowed" switch (ON by default) controls whether a
client emits all held roles or only roles from role-scope-mappings. Adopted
the **hybrid** model: a client with **no** `client_scope_roles` rows falls
back to full-scope (all held roles, current behaviour); a client with
**any** mappings switches to strict mapped-only semantics. This matches
Keycloak's default and avoids breaking existing deployments without
configuration.

### Schema

Migration `006_client_scope_roles` creates the mapping table with FK
cascades to `clients` and `roles`. SQLite 3.31-compatible (no DROP COLUMN).

### Models

- `ScopeRoleMapping` — readonly value object carrying scope, roleName,
  roleClientName (null for realm roles), and required flag.
- `IssuedGrant` — readonly value object carrying the narrowed scope string
  and `RoleClaims`.

### Resolution

`ScopeResolver::resolveIssuance()` is the single choke point for all user
flows (auth_code, refresh, offline). For each requested scope:

1. If no mappings exist for the scope, it passes through ungated.
2. If mappings exist, every `required` role must be held — if any is
   missing the whole scope is dropped.
3. Held include-mapping roles are collected into realm/client role claims.

`resource_access.<c>.roles` only emits roles whose `client_id` matches the
token's requesting client (same as full-scope behaviour). Roles mapped
under other clients' namespaces are gated but not emitted — this matches
the existing minimal `resource_access` shape and can be widened later.

### TokenService simplification

`TokenService` no longer depends on `RoleRepository` — role claim assembly
moved into `ScopeResolver::resolveIssuance()`. `GrantContext::withScope()`
returns a narrowed copy so the filtered scope propagates to all token
claims and the bundle response.

### Introspection fix

Refresh/offline introspection now reads `scope` from the decoded token
claims (`$decoded['scope']`) instead of the stored login/offline-session
row, so the introspected scope matches the issued (narrowed) scope.

### Deferred

Admin CRUD for managing `client_scope_roles` mappings is F-12 (issue 04).

### Tests

- 6 new unit tests in `ScopeResolverTest` covering full-scope fallback,
  required-role gating (held + not-held), include-mapping emission,
  unmapped scope passthrough, cross-client namespace exclusion.
- 5 new integration tests in `ScopeRoleMappingTest` covering the end-to-end
  auth_code flow with a mapped client (non-admin scope drop, admin
  scope+role include, client-role emission, refresh never-widens,
  unmapped-client full-scope fallback).
- `MigrationsEndpointTest` updated for migration 006 (count 7).
- All 507 tests green; `composer check` clean; e2e 171/171; sonar
  `--diff-ref=HEAD --fail-on-dup=3.0` exit 0.

### E2E test coverage (step 24a)

Expanded `bin/e2e-test.sh` with 5 sub-tests covering the hybrid semantics
end-to-end against a real dev server:

1. **24a-1: Full-scope fallback** — unmapped client emits all held roles
   (`admin`, `basic`) in `realm_access.roles`.
2. **24a-2: Mapped-only** — client with scope-role mappings emits only
   mapped roles the user holds; scope preserved.
3. **24a-3: Required scope kept** — required mapping satisfied (user has
   role) → scope preserved in token.
4. **24a-4: Required scope dropped** — user lacks required role → scope
   dropped from grant; `realm_access.roles` excludes unmapped role.
5. **24a-5: resource_access namespace filtering** — client role mapped to
   scope appears in `resource_access.<client>.roles` only for the
   requesting client's namespace.
