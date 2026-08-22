# ADR-0002 — SQLite compatibility floor and risky-migration release plans

- **Status:** Accepted
- **Date:** 2026-08-22
- **Decides:** which SQLite features migrations may use, and what extra work a
  risky migration owes before shipping
- **Related:** ADR-0001 (D1), `migrations/005_roles`, production hosting

## Context

Production runs on shared hosting with whatever SQLite the host's PHP bundles —
older than 3.35, no control over it. This bit for real: migration `005_roles`
originally ended with `ALTER TABLE users DROP COLUMN realm_roles`, which needs
SQLite ≥ 3.35. On production it died with `near "DROP": syntax error` and the
whole migration rolled back, leaving the role tables missing until 005 was
rewritten to retain-and-abandon the column instead.

## Decisions

### D1 — Compatibility floor: SQLite 3.31

Migrations should only use SQL constructs available in **SQLite 3.31**.
This is a tradeoff, not a hard guarantee enforced by tooling:

- No runtime version gate or static scanner — that machinery costs more than
  the risk it retires at this project's scale. Compliance is by review.
- Portable-by-default patterns are preferred: `CREATE ... IF NOT EXISTS`,
  `ALTER TABLE ... ADD COLUMN`, partial indexes, recursive CTEs.
- Destructive column removal has no portable form (`DROP COLUMN` needs 3.35;
  a table rebuild is unsafe inside the runner's transaction). The accepted
  pattern is **retain and abandon**: leave the dead column behind, never read
  or write it again.

### D2 — Risky releases require a release plan

A migration (or release) is **risky** when it performs destructive or
otherwise incompatible DB operations — dropping objects, rebuilding tables,
irreversible data transforms, or anything relying on features outside the D1
floor.

Risky releases must ship with a **release plan**, kept next to the feature's
`.scratch/<feature>/` docs, containing:

1. What the operation does and why it cannot be made portable/incremental.
2. A **precomputed list of remediation steps** to run *manually* in the SQL
   admin tool (`/admin/db`) if the automated path fails — exact SQL, ordered,
   verified against a copy of realistic data.
3. The expected post-condition of each step (what to check before continuing).

The manual list exists because hosting gives shell-less, config-blind access:
when automation dies mid-release, the admin tool is the only lever left, and
improvising destructive SQL there is how small incidents become outages.

## Consequences

- Migration reviews include a quick portability check against the D1 floor.
- Writing a release plan is part of the definition of done for any risky
  migration; a risky release without one does not ship.
