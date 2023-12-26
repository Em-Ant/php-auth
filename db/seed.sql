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
  ),
  (
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
    'realm_roles',
    'id',
    'realm_id'
  )
values(
    'emant',
    'test@example.com',
    /* plain password = tst */
    '$2y$10$b.cBLBz1//wnHmgxS8cUS.HKZFsmfT3SWYzapE6ZOuNC5GSeapHgK',
    'basic admin',
    '586d7bb3-d386-4b57-9e99-b2a460f20b47',
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  ),
  (
    'emant_test',
    'test@example.com',
    /* plain password = tst */
    '$2y$10$b.cBLBz1//wnHmgxS8cUS.HKZFsmfT3SWYzapE6ZOuNC5GSeapHgK',
    'basic admin',
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
    '$2y$10$jeRBi.jzl05D2bulVLI6zeY2BZYSGonKEY1UlEERVGpqT7peJAI.6',
    'http://localhost:5173',
    FALSE,
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f'
  ),
  (
    'df616379-3695-4466-bcda-910fcb50bb01',
    'kc_app',
    /* plain client_id = c_id */
    '$2y$10$jeRBi.jzl05D2bulVLI6zeY2BZYSGonKEY1UlEERVGpqT7peJAI.6',
    'https://www.keycloak.org/app',
    FALSE,
    'c03aa58c-2888-4f40-821c-4aadf5c58f6f'
  ),
  (
    'f83a1166-c39a-4e01-884e-bfe5073a4473',
    'playground',
    /* plain client_id = c_id */
    '$2y$10$jeRBi.jzl05D2bulVLI6zeY2BZYSGonKEY1UlEERVGpqT7peJAI.6',
    'https://em-ant.gitlab.io/react-playground',
    FALSE,
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  );