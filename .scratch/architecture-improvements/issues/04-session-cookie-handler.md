# Session cookie handler

**Status: Done**

**PRD:** Architecture Deepening
**Priority:** Low

## Problem

Session cookie encode/decode/set/delete is inline in `Authorize` controller via three private methods. The cookie format (`{realm}\{session_id}`) is implicit. Tests must mock `$_COOKIE` and `setcookie()`.

## Solution

Extract a `SessionCookieHandler` adapter behind a narrow seam.

## Created files

- `src/Interfaces/SessionCookieHandler.php`
- `src/Services/HttpSessionCookieHandler.php`
- `src/Services/InMemorySessionCookieHandler.php`

## Modified files

- `src/Controllers/Authorize.php` — inject handler, replace cookie methods
- `index.php` — create `HttpSessionCookieHandler`, inject into controller
