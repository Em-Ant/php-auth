<?php

declare(strict_types=1);

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Response\JsonResponse;
use DI\Bridge\Slim\Bridge;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;

require 'vendor/autoload.php';

$config = parse_ini_file('./config.ini', true);
$server = $config['server'];

$issuer = $server['issuer'];
$GLOBALS['sub_path'] = $server['base_path'];

$key_store = new Services\FilesystemKeyStore(__DIR__ . '/keys');

$token_service = new Services\TokenService(
    $issuer,
    $key_store
);

$log = $config['log'];
$log_print = filter_var($log['print'] ?? true, FILTER_VALIDATE_BOOLEAN);
$log_write = filter_var($log['write'] ?? false, FILTER_VALIDATE_BOOLEAN);
$logger = new Lib\Logger(
    $log['level'],
    $log_print,
    $log_write,
    date('Y-m-d') . '_' . $log['file'],
    __DIR__ . '/log'
);

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

$auth_controller = new Controllers\Authorize(
    $auth_service,
    $issuer,
    $GLOBALS['sub_path'],
    $key_store,
    $session_cookie_handler
);

// -- Slim 4 bootstrap --

$container = new \DI\Container();
$container->set(Controllers\Authorize::class, $auth_controller);

$app = Bridge::create($container);

// -- Middleware (LIFO: last added runs first) --

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

// CORS — mirrors request Origin so credentials can be safely allowed
$app->add(function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
    $origin = $request->getHeaderLine('Origin');

    if ($request->getMethod() === 'OPTIONS') {
        $response = new Response();
        $response = $response
            ->withHeader('Access-Control-Allow-Origin', $origin ?: '*')
            ->withHeader('Access-Control-Allow-Headers', 'content-type,accept,origin,authorization')
            ->withHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
            ->withStatus(204);
        if ($origin !== '') {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }
        return $response;
    }

    $response = $handler->handle($request);

    if ($origin !== '') {
        $response = $response
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Access-Control-Allow-Credentials', 'true');
    } elseif (!$response->hasHeader('Access-Control-Allow-Origin')) {
        $response = $response->withHeader('Access-Control-Allow-Origin', '*');
    }
    if (!$response->hasHeader('Access-Control-Allow-Headers')) {
        $response = $response->withHeader('Access-Control-Allow-Headers', 'content-type,accept,origin,authorization');
    }
    if (!$response->hasHeader('Access-Control-Allow-Methods')) {
        $response = $response->withHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    }

    return $response;
});

// Request logging
$app->add(function (ServerRequestInterface $request, RequestHandlerInterface $handler) use ($logger) {
    $method = $request->getMethod();
    $uri = (string) $request->getUri();
    $protocol = $request->getServerParams()['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
    $logger->info("$method $uri $protocol");
    return $handler->handle($request);
});

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

// -- Realm middleware (per-route group) --

$realmMiddleware = function (
    ServerRequestInterface $request,
    RequestHandlerInterface $handler
) use ($realm_provider): ResponseInterface {
    return $handler->handle($realm_provider->provideRealm($request));
};

// -- Routes --

// Static files
$app->get('/public/{path:.+}', function (ServerRequestInterface $request, ResponseInterface $response) {
    $path = $request->getAttribute('path');
    $file = __DIR__ . '/public/' . $path;
    if (!file_exists($file)) {
        throw new HttpNotFoundException($request, 'file not found');
    }

    $ext = pathinfo($file, PATHINFO_EXTENSION);
    $mimeTypes = [
        'css' => 'text/css',
        'js' => 'application/javascript',
        'html' => 'text/html',
        'svg' => 'image/svg+xml',
        'ico' => 'image/x-icon',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'gif' => 'image/gif',
        'woff' => 'font/woff',
        'woff2' => 'font/woff2',
    ];
    $contentType = $mimeTypes[$ext] ?? 'application/octet-stream';

    $response->getBody()->write(file_get_contents($file));
    return $response->withHeader('Content-Type', $contentType);
});

// OIDC routes (realm middleware applied to the group)
$app->group(
    '/realms/{realm}/protocol/openid-connect',
    function (\Slim\Routing\RouteCollectorProxy $group) use ($auth_controller) {
        $group->get('/auth', [$auth_controller, 'authorize']);
        $group->post('/login-actions/authenticate', [$auth_controller, 'login']);
        $group->post('/token', [$auth_controller, 'token']);
        $group->get('/logout', [$auth_controller, 'logout']);
        $group->get('/error', [$auth_controller, 'error']);
        $group->get('/certs', [$auth_controller, 'sendKeys']);
        $group->get('/userinfo', [$auth_controller, 'sendUserInfo'])
        ->add([$auth_controller, 'validateAccessTokenMiddleware']);
    }
)->add($realmMiddleware);

// Well-known config (separate route, same realm pattern)
$app->get('/realms/{realm}/.well-known/openid-configuration', [$auth_controller, 'sendConfig']);

// 3rd-party cookie check pages
$app->get('/3p-cookies/{step}', function (ServerRequestInterface $request, ResponseInterface $response) {
    $step = $request->getAttribute('step');
    $allowed = ['step1.html', 'step2.html'];
    if (!in_array($step, $allowed, true)) {
        $response->getBody()->write('Invalid step');
        return $response->withStatus(400);
    }

    $file = __DIR__ . '/src/views/3p-' . $step;
    $response->getBody()->write(file_get_contents($file));
    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
});

// Login status iframe
$app->get('/login-status-iframe.html', function (ServerRequestInterface $request, ResponseInterface $response) {
    $response->getBody()->write(file_get_contents(__DIR__ . '/src/views/login-iframe.html'));
    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
});

$app->get('/login-status-iframe.html/init', function (ServerRequestInterface $request, ResponseInterface $response) {
    return $response->withStatus(200);
});

// Adminer — included directly (handles its own routing)
$app->any('/admin', function () {
    include __DIR__ . '/db_admin/index.php';
    die();
});
$app->any('/admin/{path:.+}', function () {
    include __DIR__ . '/db_admin/index.php';
    die();
});

$app->run();
