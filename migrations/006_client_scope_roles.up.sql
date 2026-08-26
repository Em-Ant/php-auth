CREATE TABLE IF NOT EXISTS client_scope_roles (
    client_id VARCHAR(36)  NOT NULL,
    scope     VARCHAR(100) NOT NULL,
    role_id   VARCHAR(36)  NOT NULL,
    required  BOOLEAN DEFAULT 0 NOT NULL,
    PRIMARY KEY (client_id, scope, role_id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id)   REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS client_scope_roles_client_idx
    ON client_scope_roles (client_id);
