-- Reverts 010: policy columns are retained but abandoned (SQLite < 3.35
-- cannot DROP COLUMN) and reset to NULL so realms inherit the global
-- defaults again.
-- Guarded update (Sonar): reset only rows that carry an override.
UPDATE realms SET password_min_length = NULL, password_min_lower = NULL, password_min_upper = NULL, password_min_digits = NULL, password_min_special = NULL WHERE password_min_length IS NOT NULL OR password_min_lower IS NOT NULL OR password_min_upper IS NOT NULL OR password_min_digits IS NOT NULL OR password_min_special IS NOT NULL;
