# Email Verification Flow

**Status:** open — **blocked** until the mail system is ready.
**Owner:** agent + user
**Depends on:** `Mailer` interface + `NativeMailer` (email magic link,
BACKLOG **F-09**); SMTP adapter (**F-18**) for anything beyond dev.

## Problem Statement

Users carry an `email_verified` flag (bit/boolean), and `userinfo` emits it in
the `email_verified` claim for the `email` scope. Today there is **no flow that
ever makes the flag false** — the admin API defaults new users to verified and
there is no way for a user to prove email ownership. So `email_verified` is
always `true` and the claim is effectively inert.

When the flag *can* be false, consumers (and this server) need a real
verification process, otherwise the claim is misleading and the value is dead.

## User Stories

1. As an unverified user, I want to verify my email address by clicking a
   one-time link sent to that address, so the `email_verified` claim becomes
   true.
2. As an admin, I want to see a user's verification state in the admin API, so I
   can tell which addresses are proven.
3. *(future)* As an admin, I want to gate logins (ROPC / magic link) or
   privileged flows on verification when the realm requires it.

## Scope

- One-time, time-bound verification token per (user, realm).
- `POST /realms/{realm}/...`-style endpoint guarded by a token that flips
  `email_verified` to true, then the token is single-use.
- Admin API already exposes `email_verified` (read + create/update).
- `userinfo` already returns the real DB value (wired with the flag added to the
  `User` model, `UserRepository`, and admin API).

## Non-goals / consciously deferred

- **Auto-send + resend** email with the link → depends on the `Mailer`/SMTP
  system (F-09 / F-18). **This is the hard dependency.**
- Requiring verification for logins — not until a Mailer exists and realms can
  opt in.
- Un-verify / re-verify flows.

## Acceptance

1. A user with `email_verified == false` can complete verification via a
   one-time link when a Mailer is available.
2. The flag flips to true and `userinfo` / admin API reflect it.
3. Tokens are single-use and expire.

## Notes

- Until this lands, `email_verified` is kept `true` by default (hand-created
  admin users) and the claim is a no-op — documented in
  `migrations/008_email_verified_users.up.sql`.
- **Blocked:** unblock when `Mailer` exists (F-09), revisit the PRD then.
