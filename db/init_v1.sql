DROP TABLE IF EXISTS 'realms';
CREATE TABLE IF NOT EXISTS 'realms' (
  'id' VARCHAR(36) PRIMARY KEY NOT NULL,
  'name' varchar(36) NOT NULL,
  'keys_id' varchar(36) NOT NULL,
  'refresh_token_expires_in' integer NOT NULL,
  'access_token_expires_in' integer NOT NULL,
  'pending_login_expires_in' integer NOT NULL,
  'authenticated_login_expires_in' integer NOT NULL,
  'session_expires_in' integer NOT NULL,
  'idle_session_expires_in' integer NOT NULL,
  'scope' varchar(100) NOT NULL,
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX 'name_ind' ON 'realms' ('name');
DROP TABLE IF EXISTS 'users';
CREATE TABLE IF NOT EXISTS 'users' (
  'id' varchar(36) PRIMARY KEY NOT NULL,
  'realm_id' varchar(36) NOT NULL,
  'name' varchar(64),
  'email' varchar(64) UNIQUE NOT NULL,
  'password' varchar(128) NOT NULL,
  'scope' varchar(100) NOT NULL,
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'valid' integer DEFAULT "TRUE",
  FOREIGN KEY ('realm_id') REFERENCES realms('id')
);
CREATE UNIQUE INDEX 'email_ind' ON 'users' ('email');
DROP TABLE IF EXISTS 'clients';
CREATE TABLE IF NOT EXISTS 'clients' (
  'id' varchar(36) PRIMARY KEY NOT NULL,
  'name' varchar(32) NOT NULL,
  'realm_id' varchar(36) NOT NULL,
  'client_secret' varchar(64),
  'uri' varchar(256) NOT NULL,
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'require_auth' boolean DEFAULT 0,
  FOREIGN KEY ('realm_id') REFERENCES realms('id'),
  UNIQUE ('name', 'uri')
);
DROP TABLE IF EXISTS 'sessions';
CREATE TABLE IF NOT EXISTS 'sessions' (
  'id' VARCHAR(36) PRIMARY KEY NOT NULL,
  'realm_id' varchar(36) NOT NULL,
  'user_id' varchar(36) NOT NULL,
  'acr' varchar(16) NOT NULL DEFAULT '0',
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'updated_at' TIMESTAMP,
  'status' varchar(16) NOT NULL DEFAULT 'ACTIVE',
  FOREIGN KEY ('realm_id') REFERENCES realms('id'),
  FOREIGN KEY ('user_id') REFERENCES users('id')
);
DROP TABLE IF EXISTS 'logins';
CREATE TABLE IF NOT EXISTS 'logins' (
  'id' VARCHAR(36) PRIMARY KEY NOT NULL,
  'session_id' varchar(36),
  'client_id' varchar(36) NOT NULL,
  'state' varchar(256) NOT NULL,
  'nonce' varchar(256) NOT NULL,
  'scope' varchar(100) NOT NULL,
  'redirect_uri' varchar(256) NOT NULL,
  'response_mode' varchar(16) NOT NULL,
  'code' varchar(512),
  'refresh_token' varchar(2048),
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'authenticated_at' TIMESTAMP,
  'updated_at' TIMESTAMP,
  'status' varchar(16) DEFAULT 'PENDING',
  FOREIGN KEY ('client_id') REFERENCES clients('id'),
  FOREIGN KEY ('session_id') REFERENCES sessions('id')
);
CREATE UNIQUE INDEX 'code_ind' ON 'logins' ('code');
CREATE UNIQUE INDEX 'token_ind' ON 'logins' ('refresh_token');