-- Reverts 008: any verified flag is dropped back to the schema default.
-- Only safe before a real verification flow exists (per the up migration note).
-- Guarded update (Sonar): `IS NOT 0` also covers NULLs and legacy text values.
UPDATE users SET email_verified = 0 WHERE email_verified IS NOT 0;
