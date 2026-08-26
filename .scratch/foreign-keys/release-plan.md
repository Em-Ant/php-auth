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

**Prerequisite:** migration `006_client_scope_roles` must already be applied.
Verify first:

```sql
SELECT * FROM _migrations ORDER BY version DESC LIMIT 3;  -- expect 006
```

If `client_scope_roles` reports `no such table`, stop: `006` has not run
(it ships *with* this branch). Apply it first — `POST /db/migrations/migrate`
with the admin Bearer token on the staged build, or manually create it with
the exact DDL below if the automated path fails:

```sql
CREATE TABLE IF NOT EXISTS client_scope_roles (
    client_id VARCHAR(36)  NOT NULL,
    scope     VARCHAR(100) NOT NULL,
    role_id   VARCHAR(36)  NOT NULL,
    required  BOOLEAN DEFAULT 0 NOT NULL,
    PRIMARY KEY (client_id, scope, role_id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id)   REFERENCES roles(id)   ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS client_scope_roles_client_idx
    ON client_scope_roles (client_id);

-- Register the migration exactly as MigrationRunner would have
-- (version is an INTEGER, name has no numeric prefix, checksum is
-- sha256 of migrations/006_client_scope_roles.up.sql).
INSERT INTO _migrations (version, name, checksum)
VALUES (6, 'client_scope_roles',
        'a57d1c9413943d628852d96cb0851c17ab36d82c2a37f3fc1f8f3899ba67da9c');
```

*Post-condition:* `_migrations` shows version 6;
`PRAGMA foreign_key_list(client_scope_roles);` lists both FK constraints.
Then re-run the whole pre-flight.

If every query below returns `0`, deployment is safe with no remediation.

### Executed — 2026-08-26, pre-deploy

- All applicable checks returned **`0`** (users/clients/sessions, `roles`,
  `user_role_assignments`) → **no remediation needed**.
- The two `client_scope_roles` checks were reported as `no such table` —
  expected at this point: `006` ships with this branch and CI applies it
  during deploy. Vacuously clean regardless: the runner creates the table
  empty, so it can hold no orphans at birth.
- **Deploy sequence** (confirmed): FTP upload completes → server down →
  migration runs → server up. Because migration applies while the server is
  down, there is no window where new code serves against the old schema;
  FK enforcement activates directly over a referentially clean database.
- **Verdict: deployment safe.**

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

## Post-deploy verification (ordered, run immediately after server-up)

1. **Migration landed**

   ```sql
   SELECT * FROM _migrations ORDER BY version DESC LIMIT 1;  -- expect version 6
   ```
   or `GET /db/migrations/status` (admin Bearer) showing `006_client_scope_roles`
   applied. *Expected:* applied at today's timestamp, checksum
   `a57d…da9c`.

2. **FK enforcement actually firing in the app** (behavioral proof — do not
   trust `PRAGMA foreign_keys` run inside `/admin/db`: it reflects only
   *that* connection, not the app's).

   Via admin API, create a throwaway chain, then break it:

   - `POST /admin/clients` (test client, test realm)
   - `POST /admin/roles` (`client_id` = the new client)
   - `DELETE /admin/clients/{id}`

   *Expected:* the client deletes 204, and
   `GET /admin/roles?client_id={id}` then returns `{items: [], total: 0}` —
   the client-role row must be **gone via cascade**, not orphaned.
   Orphan-check SQL from the pre-flight re-run must still be all-zero
   afterwards. Clean up any leftover rows only via admin API, never raw
   DELETE (raw deletes are exactly what enforcement now forbids).

3. **Token issuance end-to-end** — mappings lookup (`findScopeRoleMappings`)
   runs on every grant, so this is the canary for `006` being present and
   readable:

   - One full login through a real client (authorize → credentials →
     token endpoint returns access/id/refresh with `scope` claim).
   - A refresh-grant call succeeds and introspection reports the narrowed
     scope.

4. **Admin surface regression sweep** — each new list endpoint answers with
   the mandated envelope:

   - `GET /admin/roles`, `GET /admin/users/{id}/roles`,
     `GET /admin/clients/{id}/scope-roles` → all return
     `{items, total, limit, offset}` with HTTP 200.

Any failure at step 2 or 3 means enforcement/migration state does not match
this plan — stop traffic investigation before touching data manually.

