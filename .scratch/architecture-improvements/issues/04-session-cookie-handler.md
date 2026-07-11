# Session cookie handler

**PRD:** Architecture Deepening
**Priority:** Low

## Problem

Session cookie encode/decode/set/delete is inline in `Authorize` controller via three private methods. The cookie format (`{realm}\{session_id}`) is implicit. Tests must mock `$_COOKIE` and `setcookie()`.

## Solution

Extract a `SessionCookieHandler` adapter behind a narrow seam.

## Interface sketch

```php
interface SessionCookieHandler {
    public function read(string $realmName): ?string; // returns session_id or null
    public function write(Realm $realm, string $sessionId): void;
    public function delete(Realm $realm): void;
}
```

Two adapters: `HttpSessionCookieHandler` (uses `$_COOKIE`/`setcookie()`), `InMemorySessionCookieHandler` for tests.

## Files

`src/controllers/authorize.php`, new files in `src/services/` or `src/lib/`
