<?php

declare(strict_types=1);

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Response\JsonResponse;
use DI\Bridge\Slim\Bridge;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;

require __DIR__ . '/../vendor/autoload.php';

$config = parse_ini_file(__DIR__ . '/../config.ini', true);
$server = $config['server'];

$issuer = $server['issuer'];
$GLOBALS['sub_path'] = $server['base_path'];

$ROOT = __DIR__ . '/..';

$key_store = new Services\FilesystemKeyStore("$ROOT/keys");

$token_service = new Services\TokenService(
    $issuer,
    $key_store
);

$log = $config['log'];
$logLevel = $log['level'] ?? 'info';
$logger = new Logger('auth');
if (filter_var($log['print'] ?? true, FILTER_VALIDATE_BOOLEAN)) {
    $logger->pushHandler(new StreamHandler('php://stdout', $logLevel));
}
if (filter_var($log['write'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
    $logger->pushHandler(new StreamHandler(
        "$ROOT/log/" . date('Y-m-d') . '_' . $log['file'],
        $logLevel
    ));
}

$admin_config = $config['admin'] ?? [];
$admin_api_key = $admin_config['api_key'] ?? '';

$password_hashing = $config['password_hashing'] ?? [];
$secrets_service = new Services\SecretsService($password_hashing);

$client_repo = new Repositories\ClientRepository(Repositories\DataSource::getInstance(), $logger);
$session_repo = new Repositories\SessionRepository(Repositories\DataSource::getInstance(), $logger);
$login_repo = new Repositories\LoginRepository(Repositories\DataSource::getInstance(), $logger);
$user_repo = new Repositories\UserRepository(Repositories\DataSource::getInstance(), $logger);
$realm_repo = new Repositories\RealmRepository(Repositories\DataSource::getInstance(), $logger);
$realm_provider = new RealmProvider($realm_repo);

$login_state_machine = new Services\LoginStateMachine(
    $login_repo,
    $logger
);

$auth_service = new Services\AuthorizeService(
    $client_repo,
    $session_repo,
    $user_repo,
    $login_repo,
    $login_state_machine,
    $secrets_service,
    $token_service,
    $logger
);

$session_cookie_handler = new Services\HttpSessionCookieHandler(
    $GLOBALS['sub_path'],
    $_SERVER['SERVER_NAME']
);

$view_renderer = new Services\ViewRenderer(
    "$ROOT/src/views",
    'template.php'
);

$auth_controller = new Controllers\Authorize(
    $auth_service,
    $issuer,
    $GLOBALS['sub_path'],
    $key_store,
    $session_cookie_handler,
    $view_renderer
);

// -- Slim 4 bootstrap --

$container = new \DI\Container();
$container->set(Controllers\Authorize::class, $auth_controller);

$app = Bridge::create($container);
$app->setBasePath($server['base_path']);

// -- Middleware (LIFO: last added runs first) --

// Error handling
$errorMiddleware = $app->addErrorMiddleware(true, true, true);

$errorMiddleware->setErrorHandler(
    HttpNotFoundException::class,
    function (
        ServerRequestInterface $request,
        \Throwable $exception,
        bool $displayErrorDetails,
        bool $logErrors,
        bool $logErrorDetails
    ) use ($logger) {
        $logger->info('404: ' . $exception->getMessage());
        $response = new Response();
        return JsonResponse::error(
            $response,
            'not found',
            $exception->getMessage(),
            404
        );
    }
);

// Body parsing (JSON content type)
$app->add(function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
    if (
        $request->getMethod() === 'POST'
        && $request->getHeaderLine('Content-Type') === 'application/json'
    ) {
        $rawBody = (string) $request->getBody();
        $data = json_decode($rawBody, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $request = $request->withParsedBody($data ?? []);
        }
    }
    return $handler->handle($request);
});

// CORS
$app->add(new CorsMiddleware());

// Request logging
$app->add(new RequestLogger($logger));

// -- Routes --

// Rate limiting
$rateLimitConfig = $config['rate_limiting'] ?? [];
$rateLimiter = new Services\RateLimiter(
    Repositories\DataSource::getInstance()->getDb()
);
$rateLimitIpSource = $rateLimitConfig['ip_source'] ?? 'remote_addr';
$rateLimits = [];
if (isset($rateLimitConfig['authenticate_limit'])) {
    $rateLimits['/login-actions/authenticate'] = [
        'max' => (int) $rateLimitConfig['authenticate_limit'],
        'window' => (int) ($rateLimitConfig['authenticate_window'] ?? 60),
    ];
}
if (isset($rateLimitConfig['token_limit'])) {
    $rateLimits['/token'] = [
        'max' => (int) $rateLimitConfig['token_limit'],
        'window' => (int) ($rateLimitConfig['token_window'] ?? 60),
    ];
}
$trustedProxies = [];
if (!empty($rateLimitConfig['trusted_proxies'])) {
    $trustedProxies = array_map('trim', explode(',', $rateLimitConfig['trusted_proxies']));
}
$rateLimitMiddleware = new Middleware\RateLimitingMiddleware(
    $rateLimiter,
    $rateLimits,
    $rateLimitIpSource,
    $trustedProxies
);

// OIDC routes (realm middleware applied to the group)
$app->group(
    '/realms/{realm}/protocol/openid-connect',
    function (\Slim\Routing\RouteCollectorProxy $group) use ($auth_controller, $auth_service, $rateLimitMiddleware) {
        $group->get('/auth', [$auth_controller, 'authorize']);
        $group->post('/login-actions/authenticate', [$auth_controller, 'login'])
            ->add($rateLimitMiddleware);
        $group->post('/token', [$auth_controller, 'token'])
            ->add($rateLimitMiddleware);
        $group->get('/logout', [$auth_controller, 'logout']);
        $group->get('/error', [$auth_controller, 'error']);
        $group->get('/certs', [$auth_controller, 'sendKeys']);
        $group->get('/userinfo', [$auth_controller, 'sendUserInfo'])
            ->add(new Middleware\ValidateAccessToken($auth_service));
    }
)->add($realm_provider);

// Well-known config
$app->get('/realms/{realm}/.well-known/openid-configuration', [$auth_controller, 'sendConfig'])
    ->add($realm_provider);

// 3rd-party cookie check pages
$app->get('/3p-cookies/{step}', function (ServerRequestInterface $request, ResponseInterface $response) {
    $step = $request->getAttribute('step');
    $allowed = ['step1.html', 'step2.html'];
    if (!in_array($step, $allowed, true)) {
        $response->getBody()->write('Invalid step');
        return $response->withStatus(400);
    }

    $file = __DIR__ . '/../src/views/3p-' . $step;
    $response->getBody()->write(file_get_contents($file));
    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
});

// Login status iframe
$app->get('/login-status-iframe.html', function (ServerRequestInterface $request, ResponseInterface $response) {
    $response->getBody()->write(file_get_contents(__DIR__ . '/../src/views/login-iframe.html'));
    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
});

$app->get('/login-status-iframe.html/init', function (ServerRequestInterface $request, ResponseInterface $response) {
    return $response->withStatus(200);
});

// Admin API — migrations management
$migration_repo = new Repositories\MigrationRepository(
    Repositories\DataSource::getInstance()->getDb()
);
$migration_runner = new Services\MigrationRunner(
    $migration_repo,
    "$ROOT/db/migrations/"
);
$migration_controller = new Controllers\Admin\MigrationsController($migration_runner);
$admin_middleware = new Middleware\AdminMiddleware($admin_api_key);

$app->group('/admin-api', function (\Slim\Routing\RouteCollectorProxy $group) use ($migration_controller) {
    $group->post('/migrations/migrate', [$migration_controller, 'migrate']);
    $group->post('/migrations/rollback', [$migration_controller, 'rollback']);
    $group->post('/migrations/go', [$migration_controller, 'go']);
    $group->get('/migrations/status', [$migration_controller, 'status']);
    $group->get('/migrations/dry-run', [$migration_controller, 'dryRun']);
})->add($admin_middleware);

// Adminer — included directly (handles its own routing)
$app->any('/admin', function () {
    include __DIR__ . '/../db_admin/index.php';
    die();
});
$app->any('/admin/{path:.+}', function () {
    include __DIR__ . '/../db_admin/index.php';
    die();
});

// Health endpoints
$app->get('/health', function (ServerRequestInterface $request, ResponseInterface $response) {
    return JsonResponse::create($response, ['status' => 'ok']);
});

$app->get('/ready', function (ServerRequestInterface $request, ResponseInterface $response) {
    try {
        $db = Repositories\DataSource::getInstance()->getDb();
        $db->query('SELECT 1');
        return JsonResponse::create($response, ['status' => 'ok']);
    } catch (\Throwable $e) {
        return JsonResponse::error(
            $response,
            'database_unreachable',
            $e->getMessage(),
            503
        );
    }
});

$app->run();
