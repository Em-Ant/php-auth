# ADR-0001 — Role storage, claim loading, and the legacy role-dialect shim

- **Status:** Accepted
- **Date:** 2026-08-21
- **Decides:** where roles live, who reads them, and the status of the
  string-based `realm_roles` admin contract
- **Supersedes:** the denormalized option in `.scratch/scopes/issues/02-client-scopes-and-roles.md`
- **Related:** migration `005_roles`, `admin-api/PRD.md`

## Context

Phase 2 of the scopes/roles roadmap needed a per-client authorization axis.
The pre-existing design stored realm roles as a space-separated string on
`users.realm_roles` (`'basic admin'`). That encoding had four defects:

1. No client-role namespace — roles could not be scoped to a single client,
   so `resource_access.<client>.roles` (Keycloak parity) was impossible.
2. No integrity: no FKs, no cascade deletes, names duplicated per user row.
3. The space separator leaked into the data model: role names could never
   contain spaces.
4. Every consumer parsed a string; nothing could answer "which users hold
   role X?" without a table scan over string munging.

Two candidate schemas existed (issue 02): a normalized Keycloak-style model
or a pragmatic JSON column on `users`. Separately, hydrating users with their
roles raised an N+1 problem, and fixing it naively (batch loading) would have
kept roles flowing through every user load forever.

## Decisions

### D1 — Normalized role tables

```text
roles(id, realm_id, client_id NULL, name, description)
user_role_assignments(user_id, role_id)
```

- `client_id IS NULL` ⇒ realm role; non-null ⇒ client role. One table serves
  both axes; two partial unique indexes keep `(realm_id, name)` and
  `(client_id, name)` unique independently.
- Migration `005_roles` moved the legacy strings into rows via recursive-CTE
  split. It originally also dropped `users.realm_roles`; amended 2026-08-22 to
  retain the column instead — `ALTER TABLE ... DROP COLUMN` needs SQLite ≥ 3.35
  and broke on shared hosting with an older bundled SQLite (the migration
  rolled back, leaving no role tables at all). The column is abandoned: no
  code reads or writes it after this migration. Environments that already
  applied the original 005 have simply dropped it; both states are valid.
- Realm roles are **not** mirrored onto clients. Client roles start empty and
  are populated explicitly (admin CRUD, F-12). An earlier implementation
  mirrored them; removed deliberately.

### D2 — User is a pure row model; claims are read at issuance

`User` carries no role state. `UserRepository` does zero role queries — this
removes the N+1 by construction rather than by batching. `TokenService`
depends on the `RoleRepository` interface and reads both role axes once per
token bundle to build `realm_access.roles` and
`resource_access.<client>.roles` (the latter only for the token's own client,
omitted when empty).

Role data has exactly two legitimate consumers: token issuance and the future
per-user role-mapping UI. Any other consumer must go through `RoleRepository`.

### D3 — Single-realm membership (Keycloak parity)

A user belongs to exactly one realm (`users.realm_id`). There is no
multi-realm membership, no cross-realm SSO, no shared roles. Realms are hard
tenants; email uniqueness is per realm. If one-human-many-realms ever becomes
a requirement, the Keycloak-shaped answer is IdP brokering with one local user
per realm — not schema changes.

### D4 — The string dialect is a shim, not architecture

The admin API still accepts `realm_roles` as a full-set, space-separated
string on user create/update. `RoleRepository::syncRealmRoles` reconciles that
desired state into rows, auto-creating unknown role names
(`ensureRealmRole`). The request dialect is preserved; the response shape is
not — user representations no longer include a `realm_roles` field, and role
state must be read through the (future F-12) role endpoints instead. This
preserves the v0 request contract, but:

- it exists solely as a compatibility layer until F-12 ships granular role
  CRUD and per-user assignment endpoints;
- new features must not extend or imitate it (no new string-encoded fields);
- when F-12 lands, auto-creation of roles from assignment requests should be
  retired — roles become explicit entities created before assignment.

## Consequences

**Positive**

- Integrity: FKs + cascades; deleting a role, client, or user cleans up after
  itself.
- Role names may contain spaces (and any other character ≤ 64 chars).
- Token issuance cost is bounded and independent of user-list operations;
  `GET /admin/users` needs no role queries at all.
- The two role axes have independent lifecycles — syncing realm roles never
  touches client assignments.

**Negative / follow-ups**

- ~~Until F-12, client roles have no write path beyond seed data.~~ — F-12
  shipped 2026-08-26 (roles CRUD + user role assignments + scope-role
  mappings).
- ~~The shim's auto-create can materialize typos as real roles~~ — retired
  2026-08-26 by F-12; `realm_roles` string field no longer accepted.
- ~~Admin list pagination and write atomicity remain open gaps~~ — pagination
  shipped with F-03 (2026-08-26); atomicity shipped with F-04.
- **Audit log on admin mutations** — compliance gap, tracked as F-07 (BACKLOG).

**Design rules (from admin-api/gaps.md, absorbed here)**

- New admin features must not reintroduce string-dialect fields (G-3 retired).
- New list endpoints ship with the `{items, total, limit, offset}` envelope
  from day one (A-03/F-03).
