INSERT INTO realms (
    'id',
    'name',
    'keys_id',
    'refresh_token_expires_in',
    'access_token_expires_in',
    'pending_login_expires_in',
    'authenticated_login_expires_in',
    'session_expires_in',
    'idle_session_expires_in'
  )
values(
    '84be68b8-7936-4422-bb4d-b741d2292a9f',
    'web',
    '33ce4036-0a36-45b9-ba74-6087d03c3b35',
    1800,
    300,
    300,
    300,
    3600 * 24,
    1800
  );
INSERT INTO realms (
    'id',
    'name',
    'keys_id',
    'refresh_token_expires_in',
    'access_token_expires_in',
    'pending_login_expires_in',
    'authenticated_login_expires_in',
    'session_expires_in',
    'idle_session_expires_in'
  )
values(
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f',
    'test',
    '2daca932-9ae0-411b-9bec-d8dac4cbe70b',
    1800,
    300,
    300,
    300,
    3600 * 24,
    1800
  );
INSERT INTO users (
    'name',
    'email',
    'password',
    'id',
    'realm_id'
  )
values(
    'emant',
    'test@example.com',
    /* plain password = tst */
    '$argon2id$v=19$m=1024,t=2,p=2$VkZ0NDBpVmlKMWIwTHgxeg$thxvsbc3yVD9DbC+FjowJ59W+orWxHCT8vuhSi6cmlk',
    '586d7bb3-d386-4b57-9e99-b2a460f20b47',
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  );
INSERT INTO users (
    'name',
    'email',
    'password',
    'id',
    'realm_id'
  )
values(
    'emant_test',
    'test@example.com',
    /* plain password = tst */
    '$argon2id$v=19$m=1024,t=2,p=2$VkZ0NDBpVmlKMWIwTHgxeg$thxvsbc3yVD9DbC+FjowJ59W+orWxHCT8vuhSi6cmlk',
    'b0aa0c22-a356-40c7-9fa2-6f973c3f614a',
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f'
  );

INSERT INTO clients (
    'id',
    'name',
    'client_secret',
    'uri',
    'require_auth',
    'realm_id'
  )
values (
    'a540c566-dfbf-430a-9941-fb8531c022d4',
    'local',
    /* plain client_id = c_id */
    '$argon2id$v=19$m=1024,t=2,p=2$YUM1NlEwLkxBS09xbGJWQw$bGDwvY/HzVl7SsOsGhgYwQkwB4QCamL/SU2EjzOtd2o',
    'http://localhost:5173/*',
    FALSE,
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f'
  ),
  (
    'df616379-3695-4466-bcda-910fcb50bb01',
    'kc_app',
    /* plain client_id = c_id */
    '$argon2id$v=19$m=1024,t=2,p=2$YUM1NlEwLkxBS09xbGJWQw$bGDwvY/HzVl7SsOsGhgYwQkwB4QCamL/SU2EjzOtd2o',
    'https://www.keycloak.org/app',
    FALSE,
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f'
  ),
  (
    'f83a1166-c39a-4e01-884e-bfe5073a4473',
    'playground',
    /* plain client_id = c_id */
    '$argon2id$v=19$m=1024,t=2,p=2$YUM1NlEwLkxBS09xbGJWQw$bGDwvY/HzVl7SsOsGhgYwQkwB4QCamL/SU2EjzOtd2o',
    'http://localhost:5173/react-playground/*',
    FALSE,
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  );

-- Realm roles
INSERT OR IGNORE INTO roles (id, realm_id, client_id, name) VALUES
  ('5a1a1000-0000-4000-8000-000000000001', '84be68b8-7936-4422-bb4d-b741d2292a9f', NULL, 'basic'),
  ('5a1a1000-0000-4000-8000-000000000002', '84be68b8-7936-4422-bb4d-b741d2292a9f', NULL, 'admin'),
  ('5a1a1000-0000-4000-8000-000000000003', 'c03aa58c-2888-4f40-821c-4aadf5c58f6f', NULL, 'basic'),
  ('5a1a1000-0000-4000-8000-000000000004', 'c03aa58c-2888-4f40-821c-4aadf5c58f6f', NULL, 'admin');

-- Client roles for kc_app (realm test)
INSERT OR IGNORE INTO roles (id, realm_id, client_id, name) VALUES
  ('5a1a1000-0000-4000-8000-000000000005', 'c03aa58c-2888-4f40-821c-4aadf5c58f6f', 'df616379-3695-4466-bcda-910fcb50bb01', 'app-user'),
  ('5a1a1000-0000-4000-8000-000000000006', 'c03aa58c-2888-4f40-821c-4aadf5c58f6f', 'df616379-3695-4466-bcda-910fcb50bb01', 'app-admin');

-- User realm-role assignments
INSERT OR IGNORE INTO user_role_assignments (user_id, role_id) VALUES
  ('586d7bb3-d386-4b57-9e99-b2a460f20b47', '5a1a1000-0000-4000-8000-000000000001'),
  ('586d7bb3-d386-4b57-9e99-b2a460f20b47', '5a1a1000-0000-4000-8000-000000000002'),
  ('b0aa0c22-a356-40c7-9fa2-6f973c3f614a', '5a1a1000-0000-4000-8000-000000000003'),
  ('b0aa0c22-a356-40c7-9fa2-6f973c3f614a', '5a1a1000-0000-4000-8000-000000000004');

-- Client-role assignment: emant_test has app-user role for kc_app
INSERT OR IGNORE INTO user_role_assignments (user_id, role_id) VALUES
  ('b0aa0c22-a356-40c7-9fa2-6f973c3f614a', '5a1a1000-0000-4000-8000-000000000005');
