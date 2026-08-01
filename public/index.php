<?php

declare(strict_types=1);

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Response\JsonResponse;
use DI\Bridge\Slim\Bridge;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;

if (function_exists('opcache_invalidate') && filter_var(ini_get('opcache.enable'), FILTER_VALIDATE_BOOLEAN)) {
    opcache_invalidate(__FILE__, true);
}

require_once __DIR__ . '/../vendor/autoload.php';

$container = require __DIR__ . '/../config/di.php';
$containerObj = new \DI\Container($container);
$app = Bridge::create($containerObj);

$basePath = $containerObj->get('base_path');
$app->setBasePath($basePath);

/** @var LoggerInterface */
$logger = $containerObj->get(LoggerInterface::class);

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
$rateLimitConfig = $containerObj->get('rate_limiting');
$rateLimiter = $containerObj->get(\AuthServer\Services\RateLimiter::class);
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
    function (\Slim\Routing\RouteCollectorProxy $group) use (
        $containerObj,
        $rateLimitMiddleware
    ) {
        $authController = $containerObj->get(Controllers\AuthorizationController::class);
        $tokenController = $containerObj->get(Controllers\TokenController::class);
        $revokeController = $containerObj->get(Controllers\RevokeController::class);
        $introspectController = $containerObj->get(Controllers\IntrospectController::class);
        $logoutController = $containerObj->get(Controllers\LogoutController::class);
        $oidcController = $containerObj->get(Controllers\OidcController::class);
        $errorController = $containerObj->get(Controllers\ErrorController::class);
        $authOrchestrator = $containerObj->get(\AuthServer\Services\AuthenticationOrchestrator::class);
        $tokenBlacklistRepo = $containerObj->get(\AuthServer\Repositories\TokenBlacklistRepository::class);
        $tokenGrantService = $containerObj->get(\AuthServer\Services\TokenGrantService::class);
        $revocationService = $containerObj->get(\AuthServer\Services\TokenRevocationService::class);
        $introspectionService = $containerObj->get(\AuthServer\Services\TokenIntrospectionService::class);

        $group->get('/auth', [$authController, 'authorize']);
        $group->post('/login-actions/authenticate', [$authController, 'login'])
            ->add($rateLimitMiddleware);
        $group->post('/token', [$tokenController, 'token'])
            ->add($rateLimitMiddleware);
        $group->post('/revoke', [$revokeController, 'revoke']);
        $group->post('/token/introspect', [$introspectController, 'introspect']);
        $group->get('/logout', [$logoutController, 'logout']);
        $group->get('/error', [$errorController, 'error']);
        $group->get('/certs', [$oidcController, 'sendKeys']);
        $group->get('/userinfo', [$oidcController, 'sendUserInfo'])
            ->add(new Middleware\ValidateAccessToken($authOrchestrator, $tokenBlacklistRepo));

        // Login status iframe (used for 3rd-party cookie detection)
        $group->get(
            '/login-status-iframe.html',
            function (ServerRequestInterface $request, ResponseInterface $response) {
                $response->getBody()->write(
                    file_get_contents(__DIR__ . '/../src/views/login-iframe.html')
                );
                return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
            }
        );

        $group->get(
            '/login-status-iframe.html/init',
            function (ServerRequestInterface $request, ResponseInterface $response) {
                return $response->withStatus(200);
            }
        );

        // 3rd-party cookie check pages
        $group->get('/3p-cookies/{step}', function (ServerRequestInterface $request, ResponseInterface $response) {
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
    }
)->add($containerObj->get(\AuthServer\Middleware\RealmProvider::class));

// Well-known config
$oidcController = $containerObj->get(Controllers\OidcController::class);
$app->get('/realms/{realm}/.well-known/openid-configuration', [$oidcController, 'sendConfig'])
    ->add($containerObj->get(\AuthServer\Middleware\RealmProvider::class));

// Admin API — migrations management
$adminMiddleware = new Middleware\AdminMiddleware($containerObj->get('admin_api_key'));
$migrationController = $containerObj->get(Controllers\Admin\MigrationsController::class);

// Migrations API (DB utility, not app-internal)
$app->group('/admin/migrations', function (\Slim\Routing\RouteCollectorProxy $group) use ($migrationController) {
    $group->post('/migrate', [$migrationController, 'migrate']);
    $group->post('/rollback', [$migrationController, 'rollback']);
    $group->post('/go', [$migrationController, 'go']);
    $group->get('/status', [$migrationController, 'status']);
    $group->get('/dry-run', [$migrationController, 'dryRun']);
})->add($adminMiddleware);

// Adminer — DB browser UI (included directly, handles its own routing)
$app->any('/admin/db', function () {
    include_once __DIR__ . '/../db_admin/index.php';
    die();
});
$app->any('/admin/db/{path:.*}', function () {
    include_once __DIR__ . '/../db_admin/index.php';
    die();
});

// Admin CRUD API (realms, clients, users, etc.)
$app->group('/api/admin', function (\Slim\Routing\RouteCollectorProxy $group) {
    // Future: realms, clients, users CRUD
})->add($adminMiddleware);

// Health endpoints
$app->get('/health', function (ServerRequestInterface $request, ResponseInterface $response) {
    return JsonResponse::create($response, ['status' => 'ok']);
});

$app->get('/ready', function (ServerRequestInterface $request, ResponseInterface $response) use ($containerObj) {
    try {
        $pdo = $containerObj->get(\PDO::class);
        $pdo->query('SELECT 1');
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
