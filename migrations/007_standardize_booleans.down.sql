-- Reverse 007: restore the legacy 'TRUE'/'FALSE' string convention on
-- users.valid. Safe with post-007 code, which reads both conventions.
UPDATE users SET valid = 'TRUE' WHERE valid = 1;

UPDATE users SET valid = 'FALSE' WHERE valid = 0;
