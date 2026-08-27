-- Reverts 008: any verified flag is dropped back to the schema default.
-- Only safe before a real verification flow exists (per the up migration note).
UPDATE users SET email_verified = 0;