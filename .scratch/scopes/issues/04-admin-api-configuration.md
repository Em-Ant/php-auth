# Admin API configuration surface for scopes/roles/mappings

status: **DONE** — 2026-08-26 (F-12). Roles CRUD, user role assignments, scope-role mappings — all shipped with 30 integration tests + 27 e2e checks.

## Problem

The scope/role model (client scopes, roles, scope↔role mappings) only exists as
DB config. Without an admin surface, nothing can manage it and the model is
dead weight. The roadmap's **Admin API** (`/api/admin`, currently an empty
group in `public/index.php`) must expose it.

## Admin entities to expose (Keycloak-flavored)

| Entity | Route(s) | Fields | Unblocks |
|---|---|---|---|
| realms | `GET/POST/PUT /api/admin/realms` | `name`, `scope`, token expiry, keys | Phase 1 (well-known via realm scope) |
| clients | `GET/POST/PUT /api/admin/clients` | `name`, `realm_id`, `uri`, `client_secret`, `require_auth`, **`scope`** | Phase 2 (client scopes) |
| roles | `GET/POST/PUT/DELETE /api/admin/roles` | `name`, `realm_id`, `client_id` (NULL = realm role) | Phase 2 (client roles) |
| user roles | `GET/POST/DELETE /api/admin/users/{id}/roles` | realm + client role assignments | Phase 2 |
| mappings | `GET/POST/PUT/DELETE /api/admin/clients/{id}/scope-roles` | `scope`, `role_id`, `required` | Phase 3 (joining config) |

All behind the existing `AdminMiddleware` (Bearer + `X-Admin-Key`), same
pattern as `/admin/migrations`.

## Ordering

1. **Realms + clients CRUD first** — minimal entities; unblocks Phase 2's
   `clients.scope` (issue 02).
2. **Roles + user role assignments** — needed for the client-role axis
   (issue 02) and for Phase 3 gating.
3. **Scope↔role mappings** — last; depends on roles existing (issue 03).

## Touch points

- `src/Controllers/Admin/` (new controllers per entity), repository CRUD
- `public/index.php` `/api/admin` group (replace the empty stub)
- `TestAppFactory` admin group (mirror, so integration tests cover it)
- `db/seed.sql` dev data for roles/mappings to make manual testing sane
- Admin API tests under `tests/Integration/Admin/`

## Acceptance

- Every scope/role/mapping value used at issuance is settable via the admin
  API (no hand-edited SQL).
- Admin CRUD is covered by integration tests with `AdminMiddleware` auth.
- All existing tests + `composer check` stay green.
