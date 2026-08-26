# 03 — Admin list endpoints: pagination + bounded payloads

status: **DONE** 08/26/2026 — uncommitted working tree (stan 0 errors, PSR12 clean, 495 tests / 1402 assertions OK, e2e 171/171)

## Outcome notes

- Paged listing lives in a `searchAll(...)` method per repository
  (`{items,total}` via `COUNT(*) OVER()`), not on `findAll`:
  sessions/logins keep unbounded `findAll` for `/admin/sessions/invalidate`,
  which legitimately needs full enumeration; users/clients lost their
  now-unused `findAll`.
- Shared plumbing: `Repositories\PagedListing` trait (query execution +
  binding) and `JsonResponse::paginated()` + `ValidatesAdminInput::paginationFromQuery()`.
- Envelope key is `items` for **all** admin list endpoints (users, clients,
  sessions, logins, offline-sessions); default limit 50, hard cap 200 — the
  offline-sessions cap was raised from 100 to align.
- Contract change applied to `bin/e2e-test.sh` list checks.

## Problem

All admin list endpoints return unbounded result sets:

- `GET /admin/users` (`UsersController::list`) — hydrates every user of the
  realm (including password hashes) into one JSON response.
- Same pattern for `GET /admin/clients`, `GET /admin/sessions`,
  `GET /admin/logins`, `GET /admin/roles` (when shipped by issue 04).

At 10k users this is a memory/time/payload blowup on every call. The auth hot
paths are unaffected (they load single rows), so this is admin-surface
reliability only — non-blocking while the admin API has no consumers.

## Target behaviour

- Bounded repository signatures:
  `findAll(?string $realmId = null, int $limit = 50, int $offset = 0)`
  (per repository; `countByRealmId()` already exists for totals).
- Controllers accept `?limit=` / `?offset=` with sane defaults and a hard cap
  (e.g. default 50, max 200); reject/handle negative offsets.
- Response envelope: `{ "users": [...], "total": N, "limit": L, "offset": O }`
  so clients can page without guessing.
- **Contract change** — any future consumer must use the envelope; fine since
  the API has no consumers yet (adminer panel used for manual ops).

## Notes

- The per-user N+1 role hydration was fixed separately in F-04 (batched
  `findRealmRoleNamesForUsers` / `findClientRoleNamesForUsers`, constant query
  count). Pagination bounds memory/payload; batching bounds queries — both are
  needed.
- Keyset pagination deliberately out of scope: LIMIT/OFFSET is adequate at the
  expected scale; revisit if realms grow past ~100k rows.
- Apply the same shape to sessions/logins/clients lists in the same pass to
  avoid two contract changes.
