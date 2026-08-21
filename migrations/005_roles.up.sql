CREATE TABLE IF NOT EXISTS roles (
    id          VARCHAR(36)  PRIMARY KEY NOT NULL,
    realm_id    VARCHAR(36)  NOT NULL,
    client_id   VARCHAR(36),
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(256),
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (realm_id)  REFERENCES realms(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS roles_realm_name_uniq
    ON roles (realm_id, name) WHERE client_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS roles_client_name_uniq
    ON roles (client_id, name) WHERE client_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_role_assignments (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Migrate the legacy space-separated users.realm_roles column into normalized
-- realm roles (client_id IS NULL), one role + assignment per name, then drop
-- the column. lower(hex(randomblob(16))) gives each role a unique opaque id.
WITH RECURSIVE split(user_id, realm_id, role, rest) AS (
    SELECT id, realm_id, '', rtrim(realm_roles) || ' '
    FROM users
    UNION ALL
    SELECT
        user_id,
        realm_id,
        substr(rest, 1, instr(rest, ' ') - 1),
        substr(rest, instr(rest, ' ') + 1)
    FROM split
    WHERE rest <> ''
)
INSERT OR IGNORE INTO roles (id, realm_id, client_id, name)
SELECT lower(hex(randomblob(16))), realm_id, NULL, role
FROM split
WHERE role <> '';

WITH RECURSIVE split(user_id, realm_id, role, rest) AS (
    SELECT id, realm_id, '', rtrim(realm_roles) || ' '
    FROM users
    UNION ALL
    SELECT
        user_id,
        realm_id,
        substr(rest, 1, instr(rest, ' ') - 1),
        substr(rest, instr(rest, ' ') + 1)
    FROM split
    WHERE rest <> ''
)
INSERT OR IGNORE INTO user_role_assignments (user_id, role_id)
SELECT s.user_id, r.id
FROM (SELECT user_id, realm_id, role FROM split WHERE role <> '') s
JOIN roles r ON r.realm_id = s.realm_id AND r.client_id IS NULL AND r.name = s.role;

ALTER TABLE users DROP COLUMN realm_roles;
