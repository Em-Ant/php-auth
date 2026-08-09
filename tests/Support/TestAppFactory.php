<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use AuthServer\Controllers\AuthorizationController;
use AuthServer\Controllers\ErrorController;
use AuthServer\Controllers\IntrospectController;
use AuthServer\Controllers\LogoutController;
use AuthServer\Controllers\OidcController;
use AuthServer\Controllers\RevokeController;
use AuthServer\Controllers\TokenController;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Middleware\AdminMiddleware;
use AuthServer\Middleware\RateLimitingMiddleware;
use AuthServer\Middleware\ValidateAccessToken;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\InMemorySessionCookieHandler;
use AuthServer\Services\Database;
use AuthServer\Services\RateLimiter;
use DI\Bridge\Slim\Bridge;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;
use AuthServer\Config\Definitions;
use AuthServer\Controllers\Admin\MigrationsController;

class TestAppFactory
{
    public static function createApp(array $overrides = []): \Slim\App
    {
        $pdo = Database::connect('sqlite::memory:');

        $pdo->exec('PRAGMA foreign_keys = ON');

        $di = Definitions::get();

        // Override PDO with in-memory SQLite
        $di[\PDO::class] = $pdo;

        // Override session cookie handler for testing
        $di[SessionCookieHandler::class] = \DI\autowire(InMemorySessionCookieHandler::class);

        // Suppress log output during tests
        $overrides['log_settings'] ??= ['print' => false, 'write' => false];

        // Apply any additional overrides
        foreach ($overrides as $key => $value) {
            $di[$key] = $value;
        }

        $container = new \DI\Container($di);
        $app = Bridge::create($container);

        // Run migrations on the in-memory database
        $migrationRepo = new \AuthServer\Repositories\MigrationRepository($pdo);
        $runner = new \AuthServer\Services\MigrationRunner(
            $migrationRepo,
            __DIR__ . '/../../migrations/'
        );
        $runner->migrate();

        // Seed data
        $seed = file_get_contents(__DIR__ . '/../../db/seed.sql');
        $pdo->exec($seed);

        $app->setBasePath($container->get('base_path'));

        $logger = $container->get(\Psr\Log\LoggerInterface::class);

        // Error handling
        $errorMiddleware = $app->addErrorMiddleware(true, true, true);
        $errorMiddleware->setErrorHandler(
            HttpNotFoundException::class,
            function (ServerRequestInterface $request, \Throwable $exception) use ($logger) {
                $response = new Response();
                return JsonResponse::error($response, 'not found', $exception->getMessage(), 404);
            }
        );
        $errorMiddleware->setErrorHandler(
            StorageFailed::class,
            function (ServerRequestInterface $request, \Throwable $exception) use ($logger) {
                $logger->error('storage failure: ' . $exception->getMessage(), [
                    'exception' => $exception,
                ]);
                $response = new Response();
                return JsonResponse::error($response, 'server_error', $exception->getMessage(), 500);
            }
        );

        // Body parsing middleware
        $app->add(function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
            $ct = $request->getHeaderLine('Content-Type');
            $rawBody = (string) $request->getBody();

            if ($request->getMethod() === 'POST' && $rawBody !== '') {
                if (str_contains($ct, 'application/json')) {
                    $data = json_decode($rawBody, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $request = $request->withParsedBody($data ?? []);
                    }
                } elseif (str_contains($ct, 'application/x-www-form-urlencoded')) {
                    parse_str($rawBody, $data);
                    $request = $request->withParsedBody($data);
                }
            }
            return $handler->handle($request);
        });

        $app->add(new CorsMiddleware());
        $app->add(new RequestLogger($logger));

        // OIDC routes
        $app->group(
            '/realms/{realm}/protocol/openid-connect',
            function (\Slim\Routing\RouteCollectorProxy $group) use ($container) {
                $authController = $container->get(AuthorizationController::class);
                $tokenController = $container->get(TokenController::class);
                $revokeController = $container->get(RevokeController::class);
                $introspectController = $container->get(IntrospectController::class);
                $logoutController = $container->get(LogoutController::class);
                $oidcController = $container->get(OidcController::class);
                $errorController = $container->get(ErrorController::class);
                $authOrchestrator = $container->get(\AuthServer\Services\AuthenticationOrchestrator::class);

                $group->get('/auth', [$authController, 'authorize']);
                $group->post('/login-actions/authenticate', [$authController, 'login']);
                $group->post('/token', [$tokenController, 'token']);
                $group->post('/revoke', [$revokeController, 'revoke']);
                $group->post('/token/introspect', [$introspectController, 'introspect']);
                $group->get('/logout', [$logoutController, 'logout']);
                $group->get('/error', [$errorController, 'error']);
                $group->get('/certs', [$oidcController, 'sendKeys']);
                $group->get('/userinfo', [$oidcController, 'sendUserInfo'])
                    ->add(new ValidateAccessToken($authOrchestrator));

                $group->get('/login-status-iframe.html', function (ServerRequestInterface $request, ResponseInterface $response) {
                    $response->getBody()->write(file_get_contents(__DIR__ . '/../../src/views/login-iframe.html'));
                    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
                });

                $group->get('/login-status-iframe.html/init', function (ServerRequestInterface $request, ResponseInterface $response) {
                    return $response->withStatus(200);
                });

                $group->get('/3p-cookies/{step}', function (ServerRequestInterface $request, ResponseInterface $response) {
                    $step = $request->getAttribute('step');
                    $allowed = ['step1.html', 'step2.html'];
                    if (!in_array($step, $allowed, true)) {
                        $response->getBody()->write('Invalid step');
                        return $response->withStatus(400);
                    }

                    $file = __DIR__ . '/../../src/views/3p-' . $step;
                    $response->getBody()->write(file_get_contents($file));
                    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
                });
            }
        )->add($container->get(RealmProvider::class));

        $app->get('/realms/{realm}/.well-known/openid-configuration', [$container->get(OidcController::class), 'sendConfig'])
            ->add($container->get(RealmProvider::class));

        // Health endpoints
        $app->get('/health', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        });

        $app->get('/ready', function (ServerRequestInterface $request, ResponseInterface $response) use ($pdo) {
            try {
                $pdo->query('SELECT 1');
                return JsonResponse::create($response, ['status' => 'ok']);
            } catch (\Throwable $e) {
                return JsonResponse::error($response, 'database_unreachable', $e->getMessage(), 503);
            }
        });

        // Admin migrations
        $adminKey = $container->get('admin_api_key');
        $migrationController = $container->get(MigrationsController::class);
        $adminMw = new AdminMiddleware($adminKey);
        $app->group('/admin/migrations', function (\Slim\Routing\RouteCollectorProxy $g) use ($migrationController) {
            $g->post('/migrate', [$migrationController, 'migrate']);
            $g->post('/rollback', [$migrationController, 'rollback']);
            $g->post('/go', [$migrationController, 'go']);
            $g->get('/status', [$migrationController, 'status']);
            $g->get('/dry-run', [$migrationController, 'dryRun']);
        })->add($adminMw);

        // Adminer
        $app->any('/admin/db', function () {
            include_once __DIR__ . '/../../db_admin/index.php';
            die();
        });
        $app->any('/admin/db/{path:.*}', function () {
            include_once __DIR__ . '/../../db_admin/index.php';
            die();
        });

        return $app;
    }
}
