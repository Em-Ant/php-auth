-- Reverse 005: drop the normalized role tables. The users.realm_roles column
-- is left as-is — 005 no longer removes it (see the note in the up file), so
-- there is nothing to restore.
DROP TABLE user_role_assignments;

DROP TABLE roles;
