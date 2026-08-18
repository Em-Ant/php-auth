ALTER TABLE realms ADD COLUMN offline_refresh_token_expires_in integer NOT NULL DEFAULT 2592000;

CREATE TABLE IF NOT EXISTS offline_sessions (
    id               VARCHAR(36)  PRIMARY KEY NOT NULL,
    realm_id         VARCHAR(36)  NOT NULL,
    user_id          VARCHAR(36)  NOT NULL,
    client_id        VARCHAR(36)  NOT NULL,
    acr              VARCHAR(16)  NOT NULL DEFAULT '0',
    scope            VARCHAR(100) NOT NULL,
    nonce            VARCHAR(256),
    refresh_token    VARCHAR(2048),
    authenticated_at TIMESTAMP,
    created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at       TIMESTAMP,
    status           VARCHAR(16)  DEFAULT 'ACTIVE',
    FOREIGN KEY (realm_id) REFERENCES realms(id),
    FOREIGN KEY (user_id)  REFERENCES users(id),
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS offline_sessions_token_ind ON offline_sessions (refresh_token);
CREATE INDEX IF NOT EXISTS offline_sessions_updated_ind ON offline_sessions (updated_at);
