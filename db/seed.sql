INSERT INTO users ('email', 'password', 'scopes', 'id')
values(
    'test@example.com',
    /* plain password = tst */
    '$2y$10$b.cBLBz1//wnHmgxS8cUS.HKZFsmfT3SWYzapE6ZOuNC5GSeapHgK',
    'admin user',
    '586d7bb3-d386-4b57-9e99-b2a460f20b47'
  );
INSERT INTO clients (
    'id',
    'client_id',
    /*'client_secret',*/
    'scopes',
    'uri'
  )
values(
    'a540c566-dfbf-430a-9941-fb8531c022d4',
    'test',
    /* plain client_id = c_id */
    /*'$2y$10$jeRBi.jzl05D2bulVLI6zeY2BZYSGonKEY1UlEERVGpqT7peJAI.6',*/
    'user',
    'http://localhost:4200'
  );