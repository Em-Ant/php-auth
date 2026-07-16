CREATE TABLE IF NOT EXISTS rate_limits (
    ip          TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ip, endpoint, window_start)
);
