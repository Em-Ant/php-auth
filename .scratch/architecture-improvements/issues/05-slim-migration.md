# Slim 4 migration

**Status: In progress**

**PRD:** Architecture Deepening
**Priority:** High

## Problem

The app uses `emant/brownie-php` as its routing/utility layer. Dependencies are wired by hand in `index.php`. Controllers receive a mutable `array $ctx` and call `die()`/`header()` directly instead of returning PSR-7 responses. No DI container, no PSR-15 middlewares, no PSR-7 request/response objects.

## Solution

Replace brownie-php with Slim 4, PHP-DI, PSR-7/PSR-15 throughout. Four phases, each demoable independently.

## Phase 1 — Foundation: Slim bootstrap + DI + PSR-7 conversion

- Add deps: `slim/slim`, `slim/psr7`, `slim/php-view`, `php-di/slim-bridge`, `monolog/monolog`
- Rewrite `index.php`: config → PHP-DI container → Slim\App → routing/error/body-parsing middleware
- Convert `Authorize` controller: PSR-7 signatures, `return ResponseInterface`, no more `die()`/`header()`/`$_GET`/`$_POST`/`$_COOKIE`
- Redirects via `$response->withHeader('Location', ...)->withStatus(302)`, JSON errors via PSR-7
- Basic auth parsing folded into `token()` method (reads `Authorization` header from `$request`)
- All existing routes work end-to-end after this phase

### Files
- `composer.json` — update deps
- `index.php` — complete rewrite
- `src/Controllers/Authorize.php` — rewrite all method signatures and internals
- `src/Middleware/RealmProvider.php` — update to use PSR-7 (attribute return, will become full middleware in Phase 3)
- `src/Services/HttpSessionCookieHandler.php` — use PSR-7 response for cookie setting
- New: `src/Response/JsonResponse.php` — helper for JSON PSR-7 responses

## Phase 2 — Views + JSON rendering

- `PhpRenderer` wrapper with `template.php` as layout
- Replace `Utils::show_view()` → `$renderer->render($response, ...)`
- Replace `Utils::send_json()` → `JsonResponse` helper
- `well-known.json` dynamic serving via reader + `<<ISSUER>>` replacement

### Files
- New: `src/Services/ViewRenderer.php` — PhpRenderer wrapper matching existing layout pattern
- `src/Controllers/Authorize.php` — replace show_view/send_json calls
- `src/views/template.php` — adapt for PhpRenderer (keep layout structure)

## Phase 3 — PSR-15 middleware stack

- `RealmProvider` → full PSR-15 middleware, `$request->withAttribute('realm', $realm)`
- `validateAccessTokenMiddleware` → PSR-15 middleware, `$request->withAttribute('accessTokenParsed', ...)`
- CORS via `tuupola/cors-middleware`
- Static file serving via `middlewares/static-files`
- Request logging via Monolog PSR-15 wrapper
- Adminer route (`/admin` include)
- `3p-cookies/{step}`, `login-status-iframe.html`, `login-status-iframe.html/init` as proper Slim routes
- Remove inline CORS/header calls from controllers

### Files
- `src/Middleware/RealmProvider.php` — full PSR-15 rewrite
- `src/Middleware/ValidateAccessToken.php` — new PSR-15 middleware (extracted from controller)
- `src/Middleware/RequestLogger.php` — new PSR-15 middleware wrapping Monolog
- `index.php` — register new middleware stack
- `src/Controllers/Authorize.php` — remove CORS/header calls, remove validateAccessToken method

## Phase 4 — Cleanup

- `get_guid()` standalone function in `src/functions.php`
- Remove `emant/brownie-php` from `composer.json`
- Remove all `use Emant\BrowniePhp\*` imports
- Remove `src/Interfaces/Logger.php` and `src/Lib/Logger.php` (replaced by Monolog)
- Final `composer check` pass

### Files
- `composer.json` — remove brownie
- New: `src/functions.php`
- `src/Services/SecretsService.php` — replace `Utils::get_guid()` with `get_guid()`
- `src/Services/TokenService.php` — replace `Utils::get_guid()` with `get_guid()`

## Acceptance criteria

- [x] Phase 1: Slim bootstraps, all auth routes respond correctly
- [x] Phase 1: No die()/header() calls in controllers
- [x] Phase 1: All request input via PSR-7 ($request methods)
- [x] Phase 2: Views render with PhpRenderer using template.php layout
- [ ] Phase 3: All PSR-15 middlewares registered and working
- [ ] Phase 3: CORS, static files, logging, Adminer, 3p/iframe all functional
- [ ] Phase 4: No emant/brownie-php references remain
- [ ] Phase 4: `composer check` passes
