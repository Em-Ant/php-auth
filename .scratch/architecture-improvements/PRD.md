# Architecture Deepening — php-auth

## Problem Statement

The auth server's architecture has four areas where modules are shallow or responsibilities are scattered, making the codebase harder to navigate, test, and modify:

- Key loading (RSA key pairs, JWKS) is duplicated across TokenService, Authorize controller, and static `createKeys()` — no seam for testing without keys on disk.
- Login state transitions (PENDING → AUTHENTICATED → ACTIVE → EXPIRED) and their TTL-based expiry rules are split across `AuthorizeService` and `LoginRepository`.
- Redirect URI construction (fragment vs query mode) is duplicated in two private methods in the Authorize controller.
- Session cookie encoding/decoding/setting/deleting is inline in the Authorize controller, coupled to `$_COOKIE` and `setcookie()`.

These are not defects — the server works. But each one makes the next change harder and keeps test coverage at zero.

## Solution

Introduce four targeted modules that deepen existing seams: KeyStore (filesystem read → repository-like seam), LoginStateMachine (state rules in one place), RedirectUri value object (pure construction), and SessionCookieHandler (infrastructure behind an adapter). Each gives a clear seam for testing without touching the filesystem, the database, or HTTP superglobals.

## User Stories

1. As a developer, I want to test token validation without RSA keys on disk, so that I can unit-test the security-critical token path.
2. As a developer, I want all login state transition rules in one module, so that I can reason about whether a login can go from AUTHENTICATED directly to EXPIRED (yes) or to PENDING (no) without reading two files.
3. As a developer, I want redirect URI construction to be a pure value object, so that the controller stops duplicating fragment/query logic.
4. As a developer, I want cookie handling behind an adapter, so that session-related tests work without `$_COOKIE` or `setcookie()` superglobals.
5. As a developer, I want each new module to have at least one alternate adapter (in-memory for tests), so that the seam is real rather than hypothetical.

## Implementation Decisions

### KeyStore

- Interface: `function findKeys(string $kid): KeySet` where `KeySet` contains `public_key`, `private_key`, `cert`, `jwks`.
- Two adapters: `FilesystemKeyStore` (reads from `keys/<kid>/`), `InMemoryKeyStore` (accepts data in constructor — for tests).
- `TokenService` receives a `KeyStore` instead of calling `file_get_contents()` directly.
- `Authorize::sendKeys()` uses `KeyStore` instead of raw `file_get_contents()`.
- `TokenService::createKeys()` stays as a setup utility, not part of the KeyStore interface.

### LoginStateMachine

- Interface: `function transition(Login $login, string $event): Login` where `event ∈ {authenticate, activate, refresh, expire, check_expiry}`.
- Single implementation that encapsulates:
  - Valid state transitions (e.g., PENDING → AUTHENTICATED, not EXPIRED → AUTHENTICATED).
  - Per-status TTL checks (moved from `AuthorizeService::checkLoginExpiration()`).
  - Side effects: calls `LoginRepository` to persist the new state.
- `AuthorizeService` delegates to this module instead of calling repository methods directly.

### RedirectUri

- Value object: `new RedirectUri(string $baseUri, string $responseMode, array $params): string`.
- `responseMode ∈ {fragment, query}` determines whether params are appended after `#` or `?`.
- Handles existing fragment in base URI correctly (same logic as current duplicated methods).
- Used by both success and error redirect paths in `Authorize` controller.

### SessionCookieHandler

- Interface: `function read(string $realmName): ?string`, `function write(Realm $realm, string $sessionId): void`, `function delete(Realm $realm): void`.
- Two adapters: `HttpSessionCookieHandler` (uses `$_COOKIE`/`setcookie()`), `InMemorySessionCookieHandler` (for tests).
- `Authorize` controller receives the handler as a constructor dependency.

## Testing Decisions

- No test suite exists in the project yet. These modules are designed to be the first testable units.
- KeyStore: `InMemoryKeyStore` makes `TokenService::validateToken()` and `TokenService::createToken()` testable without filesystem.
- LoginStateMachine: pure state-transition logic testable with a mock `LoginRepository`.
- RedirectUri: pure value object — zero dependencies, trivially testable.
- SessionCookieHandler: in-memory adapter enables controller tests without superglobals.
- The architecture review report at `.tmp/architecture-review-20260712.md` contains Mermaid diagrams for each candidate.

## Out of Scope

- Adding a test runner (PHPUnit) or writing the actual tests. This PRD only creates the seams that make testing possible.
- Merging `AuthorizeService` into the new modules — `AuthorizeService` remains as the orchestrator, delegating to the new modules.
- Replacing the brownie-php framework or its `Utils` helpers.
- Adding a dependency injection container.

## Further Notes

Each module is independent and can be implemented in any order. The recommended order is KeyStore → RedirectUri → LoginStateMachine → SessionCookieHandler, roughly from most isolated to most coupled.
