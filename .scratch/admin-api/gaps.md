# Admin API v0 — gap register

Single place for the known design gaps in the v0 admin surface. Each gap is
either tracked by a backlog row (fix later) or closed by a recorded decision
(no action). Written while the API still has **no consumers** — the point of
the register is that none of these become surprises after there are consumers.

The decisions below are formalized in `docs/adr/0001-role-storage-and-claim-loading.md`.

## Closed by decision

| # | Decision | Rationale |
|---|----------|-----------|
| D-1 | **User ↔ realm membership is fixed** (one realm per user, `users.realm_id`). No multi-realm humans, no cross-realm role sharing. | Keycloak parity. Realms are hard tenants; separate identities per realm; email uniqueness is per realm. If one-human-many-realms is ever needed, the Keycloak-shaped answer is IdP brokering with one local user per realm — not multi-membership. |
| D-2 | **Roles live only in normalized tables** (`roles`, `user_role_assignments`); `User` carries no authorization state; token claims (`realm_access`, `resource_access`) are read from the roles tables once per issuance (Option D, F-04). | Kills the per-user N+1 at the source; `UserRepository` stays a pure row mapper; role data has exactly two consumers (token claims, future admin role-mapping UI). |
| D-3 | **Role names may contain spaces** since migration 005. Any consumer still assuming the legacy space-separated encoding must not parse role *names* — only the request field below. | Was the whole point of dropping `users.realm_roles`. |

## Open gaps (tracked)

| # | Gap | Impact | Tracked by |
|---|-----|--------|------------|
| G-1 | List endpoints are unbounded (`GET /admin/users`, `/clients`, `/sessions`, `/logins`) — no pagination, no envelope. | Memory/payload blowup as data grows. | A-03 (`issues/03-pagination`) |
| G-3 | **Legacy dialect shim**: `realm_roles` accepted as a full-set, space-separated *string* on user create/update; unknown role names are auto-created on the fly (`ensureRealmRole`). Full-replace semantics, no deltas. | Last remnant of the pre-005 denormalized world. Race-prone under concurrency; typos materialize as real roles. Superseded by G-4's granular model — do not build new features on it. | To be retired by F-12; recorded in **ADR-0001 (D4)** |
| G-4 | **No role read/write surface**: no `GET /admin/roles`, no role assignment endpoints; after D-2 the user payload carries no roles, so per-user role mapping has no API yet (the future admin UI needs exactly this, per individual user). | Roles are currently manageable only via the G-3 shim (realm axis) or raw SQL (client axis). | F-12 (`scopes/issues/04`) |
| G-5 | No audit log on any admin mutation. | Compliance/debuggability once real consumers exist. | F-07 (BACKLOG) |

## Rule going forward

New admin features must not deepen G-3 (no new string-dialect fields). New
list endpoints ship with the A-03 envelope from day one.
