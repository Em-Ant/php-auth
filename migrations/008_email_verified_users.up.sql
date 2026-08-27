-- Mark all existing users as email-verified.
--
-- Users are created by hand (admin API); there is no verification flow yet, so
-- every row present before this change is by definition verified. The admin
-- create/update API defaults new users to verified=1 too.
--
-- Data transform note (ADR-0002 convention): this rewrites existing rows. The
-- down migration resets them to the schema default (0), so it is only safe to
-- roll back before a real verification flow exists.
UPDATE users SET email_verified = 1;