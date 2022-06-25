DROP TABLE IF EXISTS 'users';
CREATE TABLE IF NOT EXISTS 'users' (
  'id' varchar(36) PRIMARY KEY NOT NULL,
  'email' varchar(64) UNIQUE NOT NULL,
  'password' varchar(128) UNIQUE NOT NULL,
  'scopes' varchar(100) DEFAULT 'user',
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'valid' INTEGER DEFAULT "TRUE"
);
CREATE UNIQUE INDEX 'email_ind' ON 'users' ('email');
DROP TABLE IF EXISTS 'clients';
CREATE TABLE IF NOT EXISTS 'clients' (
  'id' varchar(36) PRIMARY KEY NOT NULL,
  'client_id' varchar(32) NOT NULL,
  'client_secret' varchar(64) NOT NULL,
  'uri' varchar(256) NOT NULL,
  UNIQUE ('client_id', 'uri')
);
DROP TABLE IF EXISTS 'sessions';
CREATE TABLE IF NOT EXISTS 'sessions' (
  'id' VARCHAR(36) PRIMARY KEY NOT NULL,
  'user_id' INTEGER default NULL,
  'client_id' INTEGER,
  'state' varchar(256) default NULL,
  'nonce' varchar(256) default NULL,
  'redirect_uri' varchar(256) default NULL,
  'code' varchar(512) default NULL,
  'refresh_token' varchar(5000) default NULL,
  'created_at' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  'status' varchar(16) DEFAULT 'PENDING',
  FOREIGN KEY ('user_id') REFERENCES users('id'),
  FOREIGN KEY ('client_id') REFERENCES clients('id')
);
CREATE UNIQUE INDEX 'code_ind' ON 'sessions' ('code');
CREATE UNIQUE INDEX 'token_ind' ON 'sessions' ('refresh_token');