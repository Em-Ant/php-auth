# Backlog — priorities + allocation policy

Single source of truth for what to work on next. **Local by design** (3 machines, no remote tracker, no `gh`/2FA) — do not "improve" this into GitHub Issues until that constraint changes.

- Detail docs stay colocated in their feature dirs (`.scratch/<feature>/`); this table only links to them.
- Edit the table to re-rank. **Done = delete the row** (git history keeps everything).
- `ROADMAP.md` stays as the product direction; this file is the executable queue.

## Policy

- **Priority drives order**: P0 (security/correctness) → P1 → P2 → P3.
- **Allocation**: when picking a week/sprint of work, target **~70% feature / ~30% refactor by size**. P0 fixes (`type=fix`) preempt the split and don't count against either bucket.
- Pick features and refactors independently from their priority order, then balance the split.

## Queue (ranked)

| ID | Type | Priority | Size | Blocked by | Why-now | Doc |
|----|------|----------|------|------------|---------|-----|
| F-56 | fix | P2 | XS | | `?target_id=` on `GET /admin/audit-logs`. Today you can filter `target_type=client` but not *which* client, so a per-resource History view means paging the whole table. The index `idx_audit_logs_target (target_type, target_id)` **already exists and the query never uses it** — so this is a param, a `WHERE` clause, a bind and a test. `audit_logs` is the one table that grows unbounded (permanent retention, purge by hand only), so it is where filtering actually pays off. Optionally `?actor_id=` on the same code path (`idx_audit_logs_actor` also exists) — weak, since `actor_id` is NULL for every static-key action | `admin-ui/API-CONTRACT.md §5.8` |
| F-57 | fix | P2 | XS | | migration `011_*` — indexes for the two hottest list queries and the new search. (a) `users(realm_id, email)`: today's index is `(email, realm_id)`, which serves `ORDER BY email` but **not** the `realm_id` filter the list query actually applies, so this composite matches filter+sort exactly. (b) `clients(realm_id, name)`: same shape — the implicit `UNIQUE(name, uri)` serves the sort but not the realm filter. (c) `users(name)`: for find-by-name search, currently unindexed. `roles` needs nothing — `roles(realm_id, name) WHERE client_id IS NULL` plus its `client_id` twin already match that list query. Portable to SQLite 3.31 (indexes only, no `ALTER`); no `UPDATE`/`DELETE`, so the Sonar `WHERE` rule is not in play | `ROADMAP → PHP 8` |
| F-53 | feature | P2 | S | | search on the two entities a human actually looks up by name: `?q=` on `GET /admin/users` (matches `email` **or** `name`) and `GET /admin/clients` (matches `name` **or** `uri`). **Prefix/type-ahead, not substring** — SQLite only uses an index for a `LIKE` with no leading wildcard, so substring is an unindexed full scan; prefix stays indexable (indexes land in F-57). **Security spec, non-negotiable:** (a) bound parameter only, never concatenate the term into SQL; (b) escape `\`, `%`, `_` in the term — backslash first — with an explicit `ESCAPE '\'` clause, so `100%` and `a_b` match literally and a caller cannot force a wildcard scan; (c) cap the term at 128 chars; (d) no `lower()` on either side, it would defeat the index — accept ASCII-only case folding and document it. **Additive**, so the FE can build without it and it lands in parallel | `admin-ui/API-CONTRACT.md §3` |
| F-09 | feature | P2 | S | | `Mailer` interface + `NativeMailer` adapter — unblocks verification (F-46) and magic link (F-51) | `ROADMAP → Login Methods` |
| F-13 | feature | P2 | S | | per-realm login page config | `ROADMAP → Login Form` |
| F-10 | feature | P2 | M | | consent screen (`offline_access`) — delayed by design; client gating (scopes #02) is the control until then | `ROADMAP → Token Lifecycle` |
| F-20 | refactor | P2 | M | | split E2E into two contracts — prod smoke (`bin/smoke-test.sh`, no DB, bounded footprint, ~30 checks) + local OIDC integrity suite; phase 2: PHPUnit-against-live-`BASE_URL` (no Playwright) — also replaces the ad-hoc `python3` JWT payload decoding in `bin/e2e-test.sh` with PHP tooling | `ci-e2e/PRD.md` |
| F-49 | feature | P2 | S–M | wait: the Admin UI is **deployed** | Narrow ops auth: `allow_all = false` so the static `api_key` works only on the ops allow-list, and move provisioning onto a JWT. **Genuinely blocked until the UI is live** — with no deployed client that can mint an admin JWT, the static key is still the *only* way to create realms/clients/users/roles/keys, which is exactly what `admin-auth/issues/bootstrap-admin-realm.sh` does. CI is **not** a blocker: deploy calls only `/admin/migrations/*`, which stays on the allow-list. Also flips two e2e assertions that currently require `allow_all = true` | `admin-auth/PRD.md #03` |
| F-14 | feature | P3 | S | | fallback full-page login form | `ROADMAP → Login Form` |
| F-18 | feature | P3 | S | | SMTP adapter (VPS) | `ROADMAP → Login Methods` |
| F-46 | feature | P3 | S | wait F-09 (Mailer) | email verification flow — one-time link flips `email_verified`; **blocked until the mail system (Mailer / SMTP) is ready**; admin API + model wiring for the flag already done | `email-verification/PRD.md` |
| F-51 | feature | P3 | M | wait F-09 (Mailer) | email magic link login (passwordless) — split out of F-09, which is now mailer-only | `ROADMAP → Login Methods` |
| F-15 | feature | P3 | L | | social login (Google/GitHub/GitLab) | `ROADMAP → Login Methods` |
| F-16 | feature | P3 | L | | 2FA/TOTP | `ROADMAP → Login Methods` |
| F-17 | feature | P3 | L | | Google-style modal widget (SAM iframe) | `ROADMAP → Login Form` |
| R-08 | refactor | P3 | S | | remaining domain enums (`ResponseMode`) | `ROADMAP → PHP 8` |
| R-13 | refactor | P3 | S | | PSR12 for `tests/` (ROADMAP "PSR12 compliance throughout" was never queued) — 198 auto-fixable violations in 25 files; run phpcbf then widen `composer cs_check` scope | `ROADMAP → PHP 8` |
| R-14 | refactor | P3 | S–M | best alongside F-51 (login-lifecycle work) | `Login` model: raw setters → intention-revealing transition methods (`markAuthenticated/markActive/markRefreshed/markExpired`), single serialization home; invariants over metric (S1448 stays, dismiss) | `login-split/PRD.md` |
| R-09 | refactor | P3 | M | | readonly props + constructor promotion | `ROADMAP → PHP 8` |
| R-10 | refactor | P3 | M | | named args + match expressions | `ROADMAP → PHP 8` |
| R-11 | refactor | P3 | L | | PHPStan 5→6→7→8→9 | `ROADMAP → PHPStan` |



**Blocked-by:** empty = pickable now; a task ID = wait for that task first.
Conscious postponements (delayed/deferred) are flagged in Why-now, not as a
status.

## Done handling

Done rows are deleted from the queue; the linked detail docs stay in their feature dirs and git history retains everything. Archive zips are unnecessary — revisit only if `.scratch/` grows unwieldy.
