# 05 — Cleanup task (blacklist + expired sessions)

status: **DONE** — delivered as `POST /admin/maintenance/cleanup` (2026-09-02, F-19)

Delivered scope (`src/Services/MaintenanceService.php` + `MaintenanceController`, wired into
`AppBuilder` under the admin auth middleware): blacklist purge (`exp < now`), login purge
mirroring `LoginStateMachine` per-status realm TTLs (EXPIRED terminal; PENDING/AUTHENTICATED/ACTIVE
past their realm TTL; ACTIVE via the sliding refresh TTL), session purge limited to EXPIRED rows
with no referencing logins (FK-safe), and offline-grant purge for terminal rows plus ACTIVE rows
past the realm sliding window (`COALESCE(updated_at, created_at)`, matching
`OfflineSessionService::isExpired`). One transaction, idempotent, returns per-table counts.
Coverage: `tests/Integration/AdminMaintenanceTest.php` + `bin/e2e-test.sh` Step 27.

## Situation

`token_blacklist` grows unbounded: every revoked access token inserts a row
(`exp` + `idx_token_blacklist_exp` exist precisely for cheap purge, but
`TokenBlacklistRepository` only has `add`/`exists`). `sessions` and `logins`
also accumulate rows in terminal/expired states.

A growing table of expired rows is not itself a blocker (the DB is effectively
infinite), but it is still worth cleaning up — which is exactly what this task
delivers. The shared server cannot run cron, so **cleanup must be an
admin-triggered maintenance task**, not a daemon.

## Delivery

Part of the Admin API workstream (same surface as offline revocation). An
admin-authenticated endpoint (or `bin/` CLI command) that:

1. Deletes `token_blacklist` rows where `exp < now()`.
2. Optionally purges expired/terminal `sessions` + `logins` older than a
   retention window (careful: `logins` reference `sessions`; pick a safe order
   and a configurable cutoff).
3. Purges `offline_sessions` where `status != 'ACTIVE'` or
   `updated_at + offline_refresh_token_expires_in < now()` (see #03). These are
   self-contained — they reference no SSO session — so no ordering concern.

Invocation options (any — whatever is available in the deployment):

- manually via admin endpoint / CLI, or
- at deployment time (part of the deploy step), or
- as a scheduled GitHub Actions job hitting the admin endpoint if possible.

## Acceptance (sketch)

- Running the task removes all blacklist rows with `exp` in the past.
- Running it is idempotent and safe to repeat; returns a summary of rows purged.
- Protected by the admin auth middleware + rate limiting (same as the rest of
  the admin surface).
