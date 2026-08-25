<?php

declare(strict_types=1);

namespace AuthServer\App;

use AuthServer\Controllers\Admin\ClientsController;
use AuthServer\Controllers\Admin\KeysController;
use AuthServer\Controllers\Admin\LoginsController;
use AuthServer\Controllers\Admin\MigrationsController;
use AuthServer\Controllers\Admin\OfflineSessionsController;
use AuthServer\Controllers\Admin\RealmsController;
use AuthServer\Controllers\Admin\SessionsController;
use AuthServer\Controllers\Admin\UsersController;
use AuthServer\Controllers\AuthorizationController;
use AuthServer\Controllers\ErrorController;
use AuthServer\Controllers\IntrospectController;
use AuthServer\Controllers\LogoutController;
use AuthServer\Controllers\OidcController;
use AuthServer\Controllers\RevokeController;
use AuthServer\Controllers\TokenController;
use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Middleware\AdminMiddleware;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RateLimitingMiddleware;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\ValidateAccessToken;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\RateLimiter;
use AuthServer\Services\TokenValidator;
use DI\Bridge\Slim\Bridge;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\App;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;
use Slim\Routing\RouteCollectorProxy;

/**
 * Single home for the Slim wiring — middleware and routes — shared by the
 * production entrypoint and the integration-test bootstrap, so a route or
 * middleware change can only ever be made once.
 *
 * The intentional environment differences are explicit:
 * - `rateLimiting`: enabled in production only (tests opt out or build their
 *   own focused apps);
 * - body parsing accepts JSON (with charset suffix) and form-encoded bodies,
 *   which is a superset of what either copy did before unification.
 */
final class AppBuilder
{
    private const PROJECT_ROOT = __DIR__ . '/../..';

    public static function create(
        ContainerInterface $container,
        bool $rateLimiting = false
    ): App {
        $app = Bridge::create($container);
        $app->setBasePath($container->get('base_path'));

        $logger = $container->get(LoggerInterface::class);

        self::registerErrorHandlers($app, $logger);

        // -- Middleware (LIFO: last added runs first) --
        $app->add(self::bodyParser());
        $app->add(new CorsMiddleware());
        $app->add(new RequestLogger($logger));

        $rateLimitMiddleware = $rateLimiting
            ? self::rateLimitMiddleware($container)
            : null;

        self::registerRoutes($app, $container, $rateLimitMiddleware);

        return $app;
    }

    private static function registerErrorHandlers(App $app, LoggerInterface $logger): void
    {
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

        // Admin API conflicts (duplicate names, guarded deletes) surface as 409.
        $errorMiddleware->setErrorHandler(
            ConflictException::class,
            function (ServerRequestInterface $request, \Throwable $exception) {
                $response = new Response();
                return JsonResponse::error($response, 'conflict', $exception->getMessage(), 409);
            }
        );

        // Infrastructure failures (DB down, ...) must surface as 500, never as 400s.
        $errorMiddleware->setErrorHandler(
            StorageFailed::class,
            function (
                ServerRequestInterface $request,
                \Throwable $exception,
                bool $displayErrorDetails,
                bool $logErrors,
                bool $logErrorDetails
            ) use ($logger) {
                $logger->error('storage failure: ' . $exception->getMessage(), [
                    'exception' => $exception,
                ]);
                $response = new Response();
                return JsonResponse::error(
                    $response,
                    'server_error',
                    $exception->getMessage(),
                    500
                );
            }
        );
    }

    private static function bodyParser(): \Psr\Http\Server\MiddlewareInterface
    {
        return new class () implements \Psr\Http\Server\MiddlewareInterface {
            public function process(
                ServerRequestInterface $request,
                \Psr\Http\Server\RequestHandlerInterface $handler
            ): ResponseInterface {
                $contentType = $request->getHeaderLine('Content-Type');
                $rawBody = (string) $request->getBody();

                if (
                    in_array($request->getMethod(), ['POST', 'PUT'], true)
                    && $rawBody !== ''
                ) {
                    if (str_contains($contentType, 'application/json')) {
                        $data = json_decode($rawBody, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $request = $request->withParsedBody($data ?? []);
                        }
                    } elseif (str_contains($contentType, 'application/x-www-form-urlencoded')) {
                        parse_str($rawBody, $data);
                        $request = $request->withParsedBody($data);
                    }
                }
                return $handler->handle($request);
            }
        };
    }

    private static function rateLimitMiddleware(ContainerInterface $container): RateLimitingMiddleware
    {
        $config = $container->get('rate_limiting');
        $rateLimits = [];
        if (isset($config['authenticate_limit'])) {
            $rateLimits['/login-actions/authenticate'] = [
                'max' => (int) $config['authenticate_limit'],
                'window' => (int) ($config['authenticate_window'] ?? 60),
            ];
        }
        if (isset($config['token_limit'])) {
            $rateLimits['/token'] = [
                'max' => (int) $config['token_limit'],
                'window' => (int) ($config['token_window'] ?? 60),
            ];
        }
        $trustedProxies = [];
        if (!empty($config['trusted_proxies'])) {
            $trustedProxies = array_map('trim', explode(',', $config['trusted_proxies']));
        }

        return new RateLimitingMiddleware(
            $container->get(RateLimiter::class),
            $rateLimits,
            $config['ip_source'] ?? 'remote_addr',
            $trustedProxies
        );
    }

    private static function registerRoutes(
        App $app,
        ContainerInterface $container,
        ?RateLimitingMiddleware $rateLimitMiddleware
    ): void {
        self::registerOidcRoutes($app, $container, $rateLimitMiddleware);
        self::registerAdminRoutes($app, $container);
        self::registerUtilityRoutes($app, $container);
    }

    private static function registerOidcRoutes(
        App $app,
        ContainerInterface $container,
        ?RateLimitingMiddleware $rateLimitMiddleware
    ): void {
        // OIDC routes (realm middleware applied to the group)
        $app->group(
            '/realms/{realm}/protocol/openid-connect',
            function (RouteCollectorProxy $group) use ($container, $rateLimitMiddleware) {
                $authController = $container->get(AuthorizationController::class);
                $tokenController = $container->get(TokenController::class);
                $revokeController = $container->get(RevokeController::class);
                $introspectController = $container->get(IntrospectController::class);
                $logoutController = $container->get(LogoutController::class);
                $oidcController = $container->get(OidcController::class);
                $errorController = $container->get(ErrorController::class);
                $tokenValidator = $container->get(TokenValidator::class);

                $group->get('/auth', [$authController, 'authorize']);
                $authenticate = $group->post('/login-actions/authenticate', [$authController, 'login']);
                $token = $group->post('/token', [$tokenController, 'token']);
                if ($rateLimitMiddleware !== null) {
                    $authenticate->add($rateLimitMiddleware);
                    $token->add($rateLimitMiddleware);
                }
                $group->post('/revoke', [$revokeController, 'revoke']);
                $group->post('/token/introspect', [$introspectController, 'introspect']);
                $group->get('/logout', [$logoutController, 'logout']);
                $group->get('/error', [$errorController, 'error']);
                $group->get('/certs', [$oidcController, 'sendKeys']);
                $group->get('/userinfo', [$oidcController, 'sendUserInfo'])
                    ->add(new ValidateAccessToken($tokenValidator));

                // Login status iframe (used for 3rd-party cookie detection)
                $group->get(
                    '/login-status-iframe.html',
                    function (ServerRequestInterface $request, ResponseInterface $response) {
                        $response->getBody()->write(
                            (string) file_get_contents(
                                self::PROJECT_ROOT . '/src/views/login-iframe.html'
                            )
                        );
                        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
                    }
                );

                $group->get(
                    '/login-status-iframe.html/init',
                    [$authController, 'loginStatusInit']
                );

                // 3rd-party cookie check pages
                $group->get('/3p-cookies/{step}', function (
                    ServerRequestInterface $request,
                    ResponseInterface $response
                ) {
                    $step = $request->getAttribute('step');
                    $allowed = ['step1.html', 'step2.html'];
                    if (!in_array($step, $allowed, true)) {
                        $response->getBody()->write('Invalid step');
                        return $response->withStatus(400);
                    }

                    $file = self::PROJECT_ROOT . '/src/views/3p-' . $step;
                    $response->getBody()->write((string) file_get_contents($file));
                    return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
                });
            }
        )->add($container->get(RealmProvider::class));

        // Well-known config
        $oidcController = $container->get(OidcController::class);
        $app->get('/realms/{realm}/.well-known/openid-configuration', [$oidcController, 'sendConfig'])
            ->add($container->get(RealmProvider::class));
    }

    private static function registerAdminRoutes(App $app, ContainerInterface $container): void
    {
        $adminMiddleware = new AdminMiddleware($container->get('admin_api_key'));
        $migrationController = $container->get(MigrationsController::class);

        // Migrations API (DB utility, not app-internal)
        $app->group('/admin/migrations', function (RouteCollectorProxy $group) use ($migrationController) {
            $group->post('/migrate', [$migrationController, 'migrate']);
            $group->post('/rollback', [$migrationController, 'rollback']);
            $group->post('/go', [$migrationController, 'go']);
            $group->get('/status', [$migrationController, 'status']);
            $group->get('/dry-run', [$migrationController, 'dryRun']);
        })->add($adminMiddleware);

        // Admin API — realms, clients, users, key assignment
        $realmsController = $container->get(RealmsController::class);
        $clientsController = $container->get(ClientsController::class);
        $usersController = $container->get(UsersController::class);
        $keysController = $container->get(KeysController::class);
        $sessionsController = $container->get(SessionsController::class);
        $loginsController = $container->get(LoginsController::class);
        $offlineSessionsController = $container->get(OfflineSessionsController::class);

        $app->group('/admin', function (RouteCollectorProxy $group) use (
            $realmsController,
            $clientsController,
            $usersController,
            $keysController,
            $sessionsController,
            $loginsController,
            $offlineSessionsController
        ) {
            $group->post('/keys', [$keysController, 'generate']);

            $group->get('/realms', [$realmsController, 'list']);
            $group->post('/realms', [$realmsController, 'create']);
            $group->get('/realms/{id}', [$realmsController, 'read']);
            $group->put('/realms/{id}', [$realmsController, 'update']);
            $group->delete('/realms/{id}', [$realmsController, 'delete']);

            $group->get('/clients', [$clientsController, 'list']);
            $group->post('/clients', [$clientsController, 'create']);
            $group->get('/clients/{id}', [$clientsController, 'read']);
            $group->put('/clients/{id}', [$clientsController, 'update']);
            $group->delete('/clients/{id}', [$clientsController, 'delete']);

            $group->get('/users', [$usersController, 'list']);
            $group->post('/users', [$usersController, 'create']);
            $group->get('/users/{id}', [$usersController, 'read']);
            $group->put('/users/{id}', [$usersController, 'update']);
            $group->delete('/users/{id}', [$usersController, 'delete']);

            $group->get('/sessions', [$sessionsController, 'list']);
            $group->delete('/sessions/{id}', [$sessionsController, 'delete']);
            $group->post('/sessions/invalidate', [$sessionsController, 'invalidate']);

            $group->get('/logins', [$loginsController, 'list']);
            $group->delete('/logins/{id}', [$loginsController, 'delete']);

            $group->get('/offline-sessions', [$offlineSessionsController, 'list']);
            $group->get('/offline-sessions/{id}', [$offlineSessionsController, 'read']);
            $group->delete('/offline-sessions/{id}', [$offlineSessionsController, 'delete']);
        })->add($adminMiddleware);
    }

    private static function registerUtilityRoutes(App $app, ContainerInterface $container): void
    {
        // Adminer — DB browser UI (included directly, handles its own routing)
        $app->any('/admin/db', function () {
            include_once self::PROJECT_ROOT . '/db_admin/index.php';
            die();
        });
        $app->any('/admin/db/{path:.*}', function () {
            include_once self::PROJECT_ROOT . '/db_admin/index.php';
            die();
        });

        // Health endpoints
        $app->get('/health', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        });

        $app->get('/ready', function (ServerRequestInterface $request, ResponseInterface $response) use ($container) {
            try {
                $pdo = $container->get(\PDO::class);
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
    }
}
