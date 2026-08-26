# Release plan — FK enforcement (`PRAGMA foreign_keys = ON`)

- **Date:** 2026-08-26
- **Risk class:** risky per ADR-0002 §D2 (behavior change over existing prod
  data; not a migration, but every pre-existing orphan row starts failing
  affected writes/deletes once enforcement is on)
- **Related:** ADR-0002 D1/D2, `src/Services/Database.php`, migration
  `005_roles`, `006_client_scope_roles`

## What changed and why

SQLite has foreign keys **OFF by default on every connection**. The schema
shipped in 005/006 relies on them for integrity and cascade deletes. Test
bootstraps enabled the pragma themselves, so all suites were green while a
production connection silently ignored cascades and let orphan rows in.
`Database::connect()` now sets `PRAGMA foreign_keys = ON` for prod parity.

The change cannot be made incremental: the pragma is per-connection and there
is no "enforce for new rows only" mode.

## Pre-flight check (run manually in `/admin/db` BEFORE deploying)

If every query below returns `0`, deployment is safe with no remediation.

```sql
-- orphan realms referenced by users / clients / sessions
SELECT COUNT(*) FROM users    WHERE realm_id NOT IN (SELECT id FROM realms);
SELECT COUNT(*) FROM clients  WHERE realm_id NOT IN (SELECT id FROM realms);
SELECT COUNT(*) FROM sessions WHERE user_id NOT IN (SELECT id FROM users);

-- role tables (005/006)
SELECT COUNT(*) FROM roles                WHERE realm_id  NOT IN (SELECT id FROM realms);
SELECT COUNT(*) FROM roles                WHERE client_id IS NOT NULL AND client_id NOT IN (SELECT id FROM clients);
SELECT COUNT(*) FROM user_role_assignments WHERE user_id NOT IN (SELECT id FROM users);
SELECT COUNT(*) FROM user_role_assignments WHERE role_id NOT IN (SELECT id FROM roles);
SELECT COUNT(*) FROM client_scope_roles   WHERE client_id NOT IN (SELECT id FROM clients);
SELECT COUNT(*) FROM client_scope_roles   WHERE role_id   NOT IN (SELECT id FROM roles);
```

## Manual remediation steps (exact SQL, ordered)

Run only for tables whose count is > 0. Expected post-condition stated per
step; re-run the matching pre-flight query after each step and expect `0`.

1. **Drop dangling role-axis orphans** (they are reconstructible via admin
   API; keeping them would poison writes later):

   ```sql
   DELETE FROM client_scope_roles WHERE role_id NOT IN (SELECT id FROM roles);
   DELETE FROM client_scope_roles WHERE client_id NOT IN (SELECT id FROM clients);
   DELETE FROM user_role_assignments WHERE role_id NOT IN (SELECT id FROM roles);
   DELETE FROM user_role_assignments WHERE user_id NOT IN (SELECT id FROM users);
   DELETE FROM roles WHERE client_id IS NOT NULL AND client_id NOT IN (SELECT id FROM clients);
   DELETE FROM roles WHERE realm_id NOT IN (SELECT id FROM realms);
   ```

   *Post-condition:* the six `user_role_assignments` / `client_scope_roles`
   / `roles` checks above all return `0`.

2. **Core-table orphans** (only if present — these should be rare):

   ```sql
   DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users);
   DELETE FROM sessions WHERE realm_id NOT IN (SELECT id FROM realms);
   DELETE FROM clients  WHERE realm_id NOT IN (SELECT id FROM realms);
   DELETE FROM logins   WHERE session_id IS NOT NULL AND session_id NOT IN (SELECT id FROM sessions);
   DELETE FROM logins   WHERE client_id NOT IN (SELECT id FROM clients);
   DELETE FROM users    WHERE realm_id NOT IN (SELECT id FROM realms);
   ```

   *Post-condition:* users/clients/sessions/logins orphan counts all `0`.
   Deletions here are auth-state only — no billing or audit data.

3. **Nothing to do** if step 1 post-condition holds but `logins` still had
   orphans *before* deploy: expired-login cleanup (F-19) is the structural
   fix; enforcement will additionally block new orphans at write time.

## Post-deploy verification

- Log in as an end user through the full OIDC flow (`composer serve` +
  `bin/e2e-test.sh` locally; prod smoke after deploy).
- Admin UI: delete a client that owns roles → its scope-role mappings and
  roles must disappear (cascades now actually fire).
