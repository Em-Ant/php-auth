# Scopes & Roles — scope/role model and mapping

## Problem Statement

The auth server is a Keycloak-style clone but its scope/role handling is a
partial, inconsistent subset:

- **Realms only**: `realms.scope` is the sole registry ("scopes this realm
  allows"). Clients have **no scope allow-list** — any client in a realm may
  request any realm scope (e.g. `admin`).
- **Duplicated validation**: the "requested ⊆ allowed" rule is implemented in
  3 places (`validateRequiredLoginScope`, `createAuthorizedLogin`,
  `getClientCredentialsTokens`).
- **Hardcoded discovery**: `static/well-known.json` hardcodes
  `scope_supported` (`["openid","profile","user","admin","read","write","acr"]`),
  which drifts from any real realm config.
- **Realm roles only**: `users.realm_roles` → `realm_access.roles`. No client
  roles, no `resource_access.<client>.roles`, no scope↔role linkage. A token
  can carry `admin` scope for a user who is not an admin; the resource server
  would have to re-check roles (there is no issuance-time gate).

## Goals

Full OAuth/OIDC scope capabilities, Keycloak-style:

1. Well-known discovery derived from real config, not hardcoded.
2. Per-client scope allow-list (clients can no longer request arbitrary scopes).
3. Both role namespaces: realm roles + client roles, delivered as
   `realm_access.roles` / `resource_access.<client>.roles`.
4. A scope↔role mapping so tokens are gated at **issuance**: scopes requiring a
   role the user lacks are dropped, and granted scopes pull in the mapped roles
   the user actually has.

## The model

Four entities:

| Entity | Storage | Meaning |
|---|---|---|
| Realm scopes | `realms.scope` (exists) | scopes the realm recognizes |
| Client scopes | `clients.scope` (new, NULL = inherit realm) | scopes a client may request |
| Realm user roles | `users.realm_roles` (exists) | who the user is, realm-wide |
| Client user roles | new | per-app authorization |

Two resolutions at token-issue time, joined by a mapping:

```
granted_scope = requested ∩ realm.scope ∩ client.scope        (capability axis)
                filtered by: scope requires role R ∧ user lacks R → drop scope

roles in token = user's roles (realm ∪ client) that are mapped
                to the granted scopes / client                 (identity axis)
                → emitted as realm_access.roles / resource_access.<client>.roles
```

Per-flow behavior:

| Flow | Dimensions in play |
|---|---|
| auth_code | full: requested ∩ realm ∩ client scopes, role-gated, both role namespaces |
| client_credentials | requested ∩ realm ∩ client scopes; **no user** → no role filtering |
| refresh | re-derive from stored granted scope — never widens |

## Phased delivery

### Phase 1 — Well-known from realm scopes (small, do first)

- `scope_supported` in discovery derived from the realm's `scope` (+ always
  `openid`), instead of the hardcoded list.
- Touch: `OidcController::sendConfig` + a placeholder in `static/well-known.json`
  (same pattern as the existing `<<ISSUER>>` replacement).
- Issue: `issues/01-well-known-from-realm-scopes.md`

### Phase 2 — Client scopes + client roles

> **Status (2026-08-07):** client-scope gating shipped (see
> [issues/02](issues/02-client-scopes-and-roles.md)). The client-role axis
> (roles table/column, `resource_access.<client>.roles`) remains.

- Add `clients.scope` (NULL = inherit realm) via migration. ✅ (migration
  `003_client_scope`)
- Introduce the client role axis:
  - Target (Keycloak-style): `roles` table (`id, realm_id, client_id NULL=realm,
    name, description`) + `user_role_assignments` (`user_id, role_id`).
  - Pragmatic alternative: keep `users.realm_roles` column, add a
    `users.client_roles` column (JSON `{client: [roles]}`) — less schema churn,
    less normalized.
- `ScopeResolver` service centralizes `requested ∩ realm ∩ client`
  (kills the 3 duplicated validations). ✅ — delivered as **strict rejection**
  of disallowed scopes (see `issues/02` Comments); `openid` implicitly allowed.
- Touch: migrations, `Client`/`User` models + repos, `config/di.php`, auth-code
  + client_credentials flows, introspection (`resource_access` passthrough).
- Issue: `issues/02-client-scopes-and-roles.md`

> **Status (2026-08-26):** Phase 3 shipped — scope↔role mapping at issuance
> with Keycloak-style full-scope fallback (no mappings = all held roles).
> Admin CRUD for mappings shipped as F-12 (issue 04, 2026-08-26).
> See [issues/03](issues/03-scope-role-mapping.md).

### Phase 3 — Scope↔role mapping (joining config, full Keycloak style)

- Client scopes carry **role scope mappings**: when a scope is granted it maps
  to roles; roles are included only if the user has them; scopes that *require*
  a role the user lacks are dropped.
- Schema: mapping table (e.g. `client_scope_roles`: `client_id, scope, role_id`
  + `required` flag).
- Composite roles (role → role) as a later refinement.
- Touch: issuance resolution in `ScopeResolver`/`TokenService`, admin CRUD,
  well-known `scope_supported` stays config-derived.
- Issue: `issues/03-scope-role-mapping.md`

## Admin API coupling (parallel track, roadmap "Admin API")

The scope/role model is **only usable if configurable**. Phases 2–3 add
admin-managed configuration, which the (not-yet-built) `/api/admin` surface
must expose — treat them as one workstream:

- **realms**: edit `scope` (allow-list) — feeds well-known.
- **clients**: edit `scope` (per-client allow-list, NULL = inherit).
- **roles**: CRUD realm roles and client roles (`roles` + assignments).
- **users**: assign realm + client roles.
- **mappings**: CRUD `client_scope_roles` per client (roles included /
  required) — the Phase 3 joining config.

Concretely: build the admin API's entities in an order that unblocks each
phase (realms/clients CRUD before Phase 2; roles + mappings before Phase 3).
Details in `issues/04-admin-api-configuration.md`.

> **Status (2026-08-26):** All admin surfaces delivered — realms/clients/users
> CRUD (F-03), session/login management (F-02), offline revocation (F-06),
> roles CRUD + user role assignments + scope-role mappings (F-12).

## Out of Scope

- Consent UI / per-user grant storage.
- Client/service-account users for `client_credentials` roles.
- Fine-grained claim protocol mappers beyond the role namespaces.

## Issues

- [#01](issues/01-well-known-from-realm-scopes.md) — Derive well-known `scope_supported` from realm scopes
- [#02](issues/02-client-scopes-and-roles.md) — Client scopes + client roles
- [#03](issues/03-scope-role-mapping.md) — Scope↔role mapping (Keycloak-style)
- [#04](issues/04-admin-api-configuration.md) — Admin API config surface for scopes/roles/mappings
