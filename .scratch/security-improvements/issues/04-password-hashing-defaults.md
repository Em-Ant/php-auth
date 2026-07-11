# Upgrade password hashing defaults

**PRD:** Security Hardening
**Priority:** Low

## Problem

Password hashing uses `PASSWORD_BCRYPT` with `cost => 10`. OWASP now recommends cost ≥ 12 for bcrypt, or preferably Argon2id. The algorithm and parameters are not configurable.

## Solution

- Switch default algorithm to `PASSWORD_ARGON2ID` with `memory_cost=1024, time_cost=2, threads=2`.
- Make algorithm and parameters configurable via `config.ini` under a `[password_hashing]` section.
- Keep `password_verify()` — it detects the algorithm from the hash string, so existing bcrypt hashes continue to work.

## Files

`src/services/secrets_service.php`, `config.ini`, `index.php`
