ALTER TABLE users ADD COLUMN realm_roles varchar(100) DEFAULT 'basic' NOT NULL;

UPDATE users
SET realm_roles = COALESCE(
    (
        SELECT group_concat(r.name, ' ')
        FROM user_role_assignments ura
        JOIN roles r ON r.id = ura.role_id
        WHERE ura.user_id = users.id AND r.client_id IS NULL
    ),
    'basic'
)
WHERE realm_roles = 'basic';

DROP TABLE user_role_assignments;

DROP TABLE roles;
