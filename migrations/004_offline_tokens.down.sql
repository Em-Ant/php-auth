DROP TABLE IF EXISTS offline_sessions;
ALTER TABLE realms DROP COLUMN offline_refresh_token_expires_in;
