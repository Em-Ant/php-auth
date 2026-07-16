# Container-driven kernel + remove DataSource singleton

**Issue**: 07  
**PRD**: Wave 2  
**Risk**: Medium (touches every file that creates services or repositories)  
**Dependencies**: None  
**Branch naming**: `refactor/container-kernel`

## Work

### Step 1 — Create `config/di.php`

Define every service, repository, and middleware as PHP-DI definitions. Use autowiring for everything that doesn't need explicit config. Register `\PDO::class` as a shared factory:

```php
\PDO::class => function () {
    $dbPath = dirname(__DIR__, 2) . '/db/data.db';
    return new \PDO("sqlite:{$dbPath}", '', '', [
        \PDO::ATTR_EMULATE_PREPARES => false,
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
    ]);
},
```

Config values (issuer, base_path, log settings, admin key, password hashing params, rate limit settings) are defined as parameters in the same file, parsed from `config.ini`.

### Step 2 — Delete `DataSource.php`

Remove `src/Repositories/DataSource.php`.

### Step 3 — Switch all repositories to `\PDO`

Change constructor signatures from `DataSource $data_source` to `\PDO $db`. Update `$this->data_source->getDb()` calls to `$this->db`.

Files affected:
- `src/Repositories/ClientRepository.php`
- `src/Repositories/SessionRepository.php`
- `src/Repositories/LoginRepository.php`
- `src/Repositories/UserRepository.php`
- `src/Repositories/RealmRepository.php`

### Step 4 — Thin `index.php`

Replace the manual `new` block (lines 31-111) with:

```php
$container = require __DIR__ . '/../config/di.php';
$app = Bridge::create(new \DI\Container($container));
$app->setBasePath($config['server']['base_path']);

// Middleware and routes stay as-is (they reference services resolved from container)
```

All middleware and route handlers resolve services from the container on demand.

### Step 5 — Create `tests/Support/TestAppFactory.php`

A helper class with:

```php
public static function createApp(array $overrides = []): \Slim\App
```

It loads `config/di.php`, overrides `\PDO::class` with an in-memory SQLite connection, runs migrations on it, and returns a fully wired Slim app.

### Step 6 — Update integration tests

`FullFlowTest`, `MigrationsEndpointTest`, `RateLimitingTest` replace their `setUpBeforeClass` bootstrap with:

```php
self::$app = TestAppFactory::createApp();
```

Remove the 100+ lines of manual construction from each file.

### Step 7 — Run full test suite

`php vendor/bin/phpunit --no-coverage` — all 193+ tests must pass.

## Verification

- [ ] `bin/migrate status` works with the container-wired runner
- [ ] `index.php` boots and all OIDC routes respond
- [ ] `FullFlowTest` passes with `TestAppFactory`
- [ ] `RateLimitingTest` passes with `TestAppFactory`
- [ ] `MigrationsEndpointTest` passes with `TestAppFactory`
- [ ] All repository unit tests still work with `\PDO` injection
