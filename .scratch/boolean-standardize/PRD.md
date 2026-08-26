# PRD: Standardize boolean columns to integer 1/0

## Problem Statement

The `users.valid` column stores booleans as string `'TRUE'`/`'FALSE'` while every other boolean in the schema (`clients.require_auth`, `client_scope_roles.required`) stores them as integer `1`/`0`. This creates inconsistency across the codebase:

- `UserRepository::userParams()` writes `'TRUE'`/`'FALSE'` strings
- `UserRepository::buildFromData()` reads with `=== 'TRUE'` strict string comparison
- `ClientRepository` and `RoleRepository` write `1`/`0` and read with `(bool)` cast
- Migration `DEFAULT 'TRUE'` stores a string literal, not a boolean value

Additionally, `users.email_verified` is a dead column — never read or written by any code.

## Solution

Standardize all boolean columns to use integer `1`/`0` convention consistently:

- `users.valid`: migration default `'TRUE'` → `1`, repository write `'TRUE'`/`'FALSE'` → `1`/`0`, repository read `=== 'TRUE'` → `(bool)`
- `users.email_verified`: drop the dead column (retain-and-abandon per ADR-0002 D1 — no `DROP COLUMN`)
- `clients.require_auth` and `client_scope_roles.required`: already correct, no changes needed

## User Stories

1. As a developer, I want all boolean columns stored as integers, so that the data layer is consistent and I don't need to remember which convention each column uses
2. As a developer, I want `UserRepository` to use the same read/write pattern as `ClientRepository`, so that adding new boolean columns doesn't require special-casing
3. As a developer, I want the dead `email_verified` column abandoned, so that future contributors aren't confused by orphaned schema
4. As a maintainer, I want a precomputed remediation plan for the migration, so that if the automated path fails on production, I can recover manually via the admin DB tool

## Implementation Decisions

- **Schema change**: `migrations/000_init_schema.up.sql` line 25: `DEFAULT 'TRUE'` → `DEFAULT 1`. This only affects fresh installs; existing data is unaffected (existing rows already have explicit string values)
- **Repository write**: `UserRepository::userParams()` line 153: change `$user->getValid() ? 'TRUE' : 'FALSE'` to `$user->getValid() ? 1 : 0`
- **Repository read**: `UserRepository::buildFromData()` line 166: change `$r['valid'] === 'TRUE'` to `(bool) $r['valid']`
- **Data migration needed**: Existing production rows have `valid = 'TRUE'` (string). A migration must update them to integer `1`. This is a **data transform** — risky per ADR-0002
- **Migration approach**: `UPDATE users SET valid = 1 WHERE valid = 'TRUE'; UPDATE users SET valid = 0 WHERE valid = 'FALSE';` — two simple UPDATE statements, idempotent, no schema rebuild
- **Dead column**: `users.email_verified` — retain-and-abandon (per ADR-0002 D1, no `DROP COLUMN`). Column stays in schema but is never touched
- **Test data**: `SessionLoginManagementTest` uses raw SQL with `'TRUE'`/`'FALSE'` strings for `valid` in 3 places — must be updated to `1`/`0`
- **Seed data**: `db/seed.sql` doesn't set `valid` explicitly, so the new default applies automatically
- **Migration ordering**: New migration file (e.g., `007_standardize_booleans.up.sql`) that transforms existing data. The init migration fix is for fresh installs only

## Testing Decisions

- Existing `UserAdminServiceTest::testUpdateUserPersistsChangesAndRolesTogether` covers the full create→update→read cycle with `valid = false` — this test validates the fix end-to-end
- `SessionLoginManagementTest` tests login with disabled/enabled users — covers both `valid = true` and `valid = false` paths through the repository
- `FullFlowTest` integration tests exercise the full OIDC flow which touches user lookup — regression coverage
- Unit tests for `UserRepository` don't exist yet; consider adding one to verify `buildFromData` handles both old string values and new integer values (graceful transition)

## Out of Scope

- Dropping `email_verified` column (requires schema rebuild, tracked separately if ever needed)
- Standardizing `email_verified` default (column is dead code, not worth touching)
- Touching `clients.require_auth` or `client_scope_roles.required` (already correct)
- Changing any model classes (User model already returns `bool` from `getValid()`)

## Further Notes

- This is a **risky migration** per ADR-0002: it performs a data transform on a production table. A release plan with precomputed remediation SQL is required before shipping.
- The init migration change (`DEFAULT 'TRUE'` → `DEFAULT 1`) only matters for fresh installs. Existing databases keep their string values until the data migration runs.
- Priority: P1 — code consistency issue that doesn't affect correctness (strings work, they're just wrong convention), but blocks clean future boolean work.
