-- F-57: indexes for the two hottest admin list queries and the F-53 prefix search.
-- (a) users(realm_id, email): matches the list filter (realm_id) + sort (email)
-- exactly. The existing email_ind (email, realm_id) serves ORDER BY but not the
-- filter, and stays: it enforces per-realm email uniqueness.
-- (b) clients(realm_id, name): same shape; UNIQUE(name, uri) serves the sort
-- but not the realm filter.
-- (c) users(name): for the name branch of the F-53 ?q= search (email OR name).
-- Indexes only: portable to SQLite 3.31, no UPDATE/DELETE.
CREATE INDEX IF NOT EXISTS idx_users_realm_email ON users (realm_id, email);
CREATE INDEX IF NOT EXISTS idx_clients_realm_name ON clients (realm_id, name);
CREATE INDEX IF NOT EXISTS idx_users_name ON users (name);
