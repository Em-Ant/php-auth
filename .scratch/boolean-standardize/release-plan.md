# Release plan — migration 007 `standardize_booleans`

Per ADR-0002 D2: this release is **risky** because it performs a data
transform on a production table (`users.valid`: string `'TRUE'`/`'FALSE'` →
integer `1`/`0`). This document is part of its definition of done.

## 1. What the operation does, and why it ships this way

Two idempotent statements:

```sql
UPDATE users SET valid = 1 WHERE valid = 'TRUE';
UPDATE users SET valid = 0 WHERE valid = 'FALSE';
```

- It cannot be made incremental: old rows carry TEXT values that no code path
  writes anymore once this release is deployed; the transform must sweep the
  table exactly once.
- There is no schema change and no table rebuild — SQLite-portable at any
  version ≥ 3.31 (plain UPDATEs), runs inside the runner's transaction like
  every other migration.
- The statements are idempotent: re-running them (or running them on a fresh
  install where 000 now defines `DEFAULT 1`) matches zero rows.

### Deployment order and code coupling

`UserRepository::readValid()` in the same release reads **both** conventions,
so uploading files before running the migration is safe; a disabled user stays
disabled during the window between deploy and
`POST /db/migrations/migrate`. Downgrading to pre-007 code after the migration
ran is also safe for reads (old code's `=== 'TRUE'` still matches nothing of
`0`, which only disables users that were already disabled… except it reads
`1` as invalid) — if a rollback of *code* is needed without restoring data,
run the down migration or the remediation below first.

## 2. Precomputed remediation steps (manual, via `/admin/db`)

Run these **only** if the automated path failed mid-release.

### Step 0 — Assess

```sql
SELECT valid, COUNT(*) FROM users GROUP BY valid;
```

Expected post-condition: shows what state the rows are in. Healthy states:
only `1`/`0` (done), only `'TRUE'`/`'FALSE'` (not yet migrated), or a mix
(partial). Anything else needs investigation before proceeding.

### Step 1 — Re-run the transform manually

```sql
UPDATE users SET valid = 1 WHERE valid = 'TRUE';
UPDATE users SET valid = 0 WHERE valid = 'FALSE';
```

Expected post-condition: each statement reports success with no error;
re-running the Step 0 query now groups rows into only `1` and `0`.

### Step 2 — Clear the recorded migration so the runner bookkeeping matches

```sql
DELETE FROM migrations WHERE name LIKE '%007%';
```

(Adjust the table/column names to whatever the schema migration ledger uses;
inspect with `.schema`-equivalent introspection in the admin tool first.)
Expected post-condition: zero rows referencing 007. The next automated
migration run will then apply 007 cleanly as an idempotent no-op on data and
record it.

> If migration `000_init_schema.up.sql` itself had not yet been applied
> (impossible on existing installs) there is nothing to remediate here:
> fresh installs are created directly with the integer convention.

## 3. Rollback

Down migration `007_standardize_booleans.down.sql` restores the legacy strings
(`WHERE valid = 1 / = 0`). Post-condition: Step 0 groups show only
`'TRUE'`/`'FALSE'`.
