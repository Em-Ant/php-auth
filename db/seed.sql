INSERT OR IGNORE INTO realms (
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
INSERT OR IGNORE INTO realms (
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
INSERT OR IGNORE INTO users (
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
INSERT OR IGNORE INTO users (
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

INSERT OR IGNORE INTO clients (
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
-- Seed users are created by hand, so they are email-verified. The admin API
-- defaults new users to verified=1 too (no verification flow exists yet).
-- Guarded update (Sonar): touches every non-verified row, NULL included.
UPDATE users SET email_verified = 1 WHERE email_verified IS NOT 1;

-- ---------------------------------------------------------------------------
-- Admin realm (F-47 dev seed only). Backing data for the Admin UI (SSO + PKCE)
-- and headless CI (offline) auth once the admin-auth middleware (issue #02)
-- lands. Inert without it. Prod NEVER runs seed.sql; it bootstraps via the
-- admin API runbook (admin-auth/issues/04-prod-bootstrap-runbook.md).
-- All statements are INSERT OR IGNORE with fixed PKs, so re-running is safe.
-- ---------------------------------------------------------------------------

-- Admin realm: owns admin users/clients/roles; supports SSO + offline like any
-- realm (no special flag). realm scope includes offline_access so the per-client
-- gate (scopes #02) can allow it for ci-deployer only, not admin-ui.
INSERT OR IGNORE INTO realms (
    id, name, keys_id,
    refresh_token_expires_in, access_token_expires_in,
    pending_login_expires_in, authenticated_login_expires_in,
    session_expires_in, idle_session_expires_in,
    scope
) VALUES (
    'adc8cc40-943c-4fa4-97ed-2777baa49db5', 'admin',
    '787248fe-344f-4db3-a287-daef099867c6',
    1800, 300, 300, 300,
    3600 * 24, 1800,
    'openid profile email offline_access'
);

-- Realm role 'admin' (client_id IS NULL -> realm role).
INSERT OR IGNORE INTO roles (id, realm_id, client_id, name) VALUES
  ('25aaf5eb-406b-4d86-a01e-db940e0002f1',
   'adc8cc40-943c-4fa4-97ed-2777baa49db5', NULL, 'admin');

-- admin-ui: public, PKCE, NO offline_access.
INSERT OR IGNORE INTO clients (id, name, realm_id, client_secret, uri, require_auth, scope) VALUES
  ('8d8dbe43-1257-4f00-9ef0-0d3d15a34207', 'admin-ui',
   'adc8cc40-943c-4fa4-97ed-2777baa49db5', NULL,
   'http://localhost:5173/*', 0, 'openid profile email');

-- ci-deployer: confidential, WITH offline_access (dev placeholder secret;
-- plain text = ci-deployer-dev-secret; prod generates a strong value via the
-- runbook and hashes it server-side, never reuses this dev hash).
INSERT OR IGNORE INTO clients (id, name, realm_id, client_secret, uri, require_auth, scope) VALUES
  ('5eccaf8a-6f2d-489e-b29c-832f86ef507c', 'ci-deployer',
   'adc8cc40-943c-4fa4-97ed-2777baa49db5',
   '$argon2id$v=19$m=1024,t=2,p=2$RUxrZ3Z0UzcvLi9XOHZrRQ$S7xt8rgPz3DJlw2PT/BVTIMdnbnGrU/pMRLANrfBO7s',
   'http://localhost/ci', 1, 'openid profile email offline_access');

-- Bootstrap admin user (dev-only; plain text password = ChangeMe!dev; prod
-- bootstraps via admin API runbook).
INSERT OR IGNORE INTO users (id, realm_id, name, email, password, realm_roles, email_verified, valid) VALUES
  ('4a8b6d24-611f-45ca-a2b9-d272fa7a7f5d',
   'adc8cc40-943c-4fa4-97ed-2777baa49db5', 'admin', 'admin@example.com',
   '$argon2id$v=19$m=1024,t=2,p=2$ZmQuZ0UuNTF3c1ZZMnRxcw$Fd9VMo9mHW9bGrpNxdzMyNgMF8oh6sicFRctedTayI0',
   'basic', 1, 1);

-- Assign the admin realm role to the bootstrap admin user.
INSERT OR IGNORE INTO user_role_assignments (user_id, role_id) VALUES
  ('4a8b6d24-611f-45ca-a2b9-d272fa7a7f5d',
   '25aaf5eb-406b-4d86-a01e-db940e0002f1');
