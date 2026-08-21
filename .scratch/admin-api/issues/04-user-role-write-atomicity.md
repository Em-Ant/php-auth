# 04 — Atomic user create/update with role assignments

status: **OPEN**

## Problem

The admin user write path runs two statements without a wrapping
transaction:

- `UsersController::create` — `users` INSERT, then `RoleRepository::syncRealmRoles`
- `UsersController::update` — `users` UPDATE, then `syncRealmRoles`

(`syncRealmRoles` opens its own transaction internally; the gap is *between*
the user row write and the role sync.) A failure in between leaves a user
without realm roles on create, or silently drops the intended role change on
update.

Low practical risk today (SQLite, single process, local disk), but it breaks
the write contract: half of the operation can persist while the other half
fails.

## Fix

- Wrap each pair in one transaction spanning both writes. Cleanest shape:
  move the orchestration into a small domain service (or repository method)
  that owns the transaction — controllers should not manage transactions.
- Watch for nested-transaction pitfalls if `syncRealmRoles` keeps its internal
  `beginTransaction`: either hoist the transaction to the caller and drop the
  inner one, or add savepoint/re-entrant handling.
- Same pattern check for future writers (issue 04 roles CRUD will touch the
  same tables).

## Notes

- Found during F-04 review (pre-Option-D, when `UserRepository` orchestrated
  the sync; the gap survived the Option D move to the controller).
- Non-blocking: auth hot paths never call this code; admin API has no
  consumers yet.
