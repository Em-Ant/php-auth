INSERT INTO realms (
    'id',
    'name',
    'keys_id',
    'refresh_token_expires_in',
    'access_token_expires_in',
    'pending_login_expires_in',
    'authenticated_login_expires_in',
    'session_expires_in',
    'idle_session_expires_in',
    'scopes'
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
    1800,
    'admin user'
  );
INSERT INTO users (
    'name',
    'email',
    'password',
    'scopes',
    'id',
    'realm_id'
  )
values(
    'emant',
    'test@example.com',
    /* plain password = tst */
    '$2y$10$b.cBLBz1//wnHmgxS8cUS.HKZFsmfT3SWYzapE6ZOuNC5GSeapHgK',
    'admin user',
    '586d7bb3-d386-4b57-9e99-b2a460f20b47',
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  );
INSERT INTO clients (
    'id',
    'name',
    'client_secret',
    'uri',
    'require_auth',
    'realm_id'
  )
values(
    'a540c566-dfbf-430a-9941-fb8531c022d4',
    'test',
    /* plain client_id = c_id */
    '$2y$10$jeRBi.jzl05D2bulVLI6zeY2BZYSGonKEY1UlEERVGpqT7peJAI.6',
    'http://localhost:4200',
    'FALSE',
    '84be68b8-7936-4422-bb4d-b741d2292a9f'
  );