-- Reverts 011: search indexes are advisory only, dropping them changes no data.
DROP INDEX IF EXISTS idx_users_name;
DROP INDEX IF EXISTS idx_clients_realm_name;
DROP INDEX IF EXISTS idx_users_realm_email;
