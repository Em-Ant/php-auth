# Wave 2 — Bootstrap, DI, and Service Splitting

## Problem Statement

The codebase works but has three structural issues that make each change harder:

- ~~**God class**: `AuthorizeService` (712 lines) mixed input validation, business orchestration, session management, and persistence.~~ ✅ Split into `InputValidator`, `SessionOrchestrator`, `AuthenticationOrchestrator`.
- **Decorative DI**: The container holds one entry. Everything is wired manually in `index.php`, and every integration test duplicates this bootstrap. Adding a dependency means editing 4 files.
- **Singleton global state**: `DataSource` is a singleton enforcing one connection, with a `$testPdo` static hack for tests that causes pollution across suites.
- **Schema duplication**: `db/init_v1.sql` removed — schema now lives only in migrations.

## User Stories

1. As a developer, I want `index.php` to be thin (config → container → run), so that I can add a new service without touching the entrypoint.
2. As a developer, I want a `TestAppFactory` so that integration tests don't duplicate the 100-line bootstrap.
3. As a developer, I want repository constructors to take `\PDO` directly, so that they declare their real dependency instead of a singleton wrapper.
4. ~~As a developer, I want `AuthorizeService` split into `InputValidator`, `SessionOrchestrator`, and `AuthenticationOrchestrator`, so that I can test validation (zero mocks) and orchestration (narrow mocks) separately.~~ ✅
5. ~~As a developer, I want domain exceptions without HTTP status codes baked in, so they make sense in CLI or async contexts too.~~ ✅

## Implementation Decisions

### Container-driven kernel

- PHP-DI definitions live in `config/di.php` returning an array of definitions.
- Every service, repository, and middleware is defined there. Auto-wiring handles constructor injection.
- `\PDO::class` is registered as a shared factory.
- `index.php` shrinks to ~40 lines: load config, build container from `config/di.php`, create app, register routes, run.
- `TestAppFactory` in `tests/Support/TestAppFactory.php` creates a container overriding `\PDO::class` with in-memory SQLite + runs migrations. Integration tests call one method instead of duplicating bootstrap.

### Remove DataSource singleton

- Delete `src/Repositories/DataSource.php`.
- All repositories currently taking `DataSource $ds` switch to `\PDO $db`. (`MigrationRepository`, `RateLimiter` already do this.)
- Update `index.php` and all test bootstraps to pass `\PDO` directly.

### Split AuthorizeService ✅

- **`InputValidator`** — pure public static methods extracted from `AuthorizeService`'s private helpers. Zero dependencies.
- **`SessionOrchestrator`** — session lifecycle: `ensureValid`, `checkExpiry` (pure, CQS), `expire` (explicit mutation).
- **`AuthenticationOrchestrator`** — coordinates login/token/refresh/logout flows.
- **Exceptions** — `InvalidInputException`, `StorageErrorException`, `CriticalLoginErrorException` replaced with `ValidationFailed`, `AuthenticationFailed`, `StorageFailed` (no HTTP status codes).

## Out of Scope

- Pruning shallow interfaces (ClientRepository, RealmRepository, UserRepository, KeyStore).
- Replacing cookie superglobal coupling.
- Adding a query builder or ORM.
- Changing the migration system.

## Testing Decisions

- `TestAppFactory::createApp()` returns fully wired Slim app with in-memory SQLite + migrations.
- `InputValidator` tests need zero mocks. ✅
- `SessionOrchestrator` tests need mock `SessionRepository`. ✅
- `AuthenticationOrchestrator` tests use `TestAppFactory` or mock its dependencies. ✅
- Existing integration tests switch to `TestAppFactory`, removing ~200 lines of duplicate bootstrap.

## Issues

- [#07](issues/07-container-kernel.md) — Container kernel + remove DataSource
