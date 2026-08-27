-- Standardize users.valid to the integer 1/0 boolean convention used by every
-- other boolean column (clients.require_auth, client_scope_roles.required).
-- Rows written before this migration hold the string literals 'TRUE'/'FALSE'
-- (NUMERIC affinity keeps them as TEXT). The statements are idempotent and
-- no-op on rows already using the integer convention — including fresh
-- installs, where 000_init_schema.up.sql now defines DEFAULT 1.
-- Risky data transform: release plan in .scratch/boolean-standardize/release-plan.md.
UPDATE users SET valid = 1 WHERE valid = 'TRUE';

UPDATE users SET valid = 0 WHERE valid = 'FALSE';
