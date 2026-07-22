<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use AuthServer\Controllers\AuthorizationController;
use AuthServer\Controllers\ErrorController;
use AuthServer\Controllers\LogoutController;
use AuthServer\Controllers\OidcController;
use AuthServer\Controllers\TokenController;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Middleware\ValidateAccessToken;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\InMemorySessionCookieHandler;
use DI\Bridge\Slim\Bridge;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Response;

class TestAppFactory
{
    public static function createApp(array $overrides = []): \Slim\App
    {
        $pdo = new \PDO('sqlite::memory:', '', '', [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $pdo->exec('PRAGMA foreign_keys = ON');

        $di = require __DIR__ . '/../../config/di.php';

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
            __DIR__ . '/../../db/migrations/'
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
                $logoutController = $container->get(LogoutController::class);
                $oidcController = $container->get(OidcController::class);
                $errorController = $container->get(ErrorController::class);
                $authOrchestrator = $container->get(\AuthServer\Services\AuthenticationOrchestrator::class);

                $group->get('/auth', [$authController, 'authorize']);
                $group->post('/login-actions/authenticate', [$authController, 'login']);
                $group->post('/token', [$tokenController, 'token']);
                $group->get('/logout', [$logoutController, 'logout']);
                $group->get('/error', [$errorController, 'error']);
                $group->get('/certs', [$oidcController, 'sendKeys']);
                $group->get('/userinfo', [$oidcController, 'sendUserInfo'])
                    ->add(new ValidateAccessToken($authOrchestrator));
            }
        )->add($container->get(RealmProvider::class));

        $app->get('/realms/{realm}/.well-known/openid-configuration', [$container->get(OidcController::class), 'sendConfig'])
            ->add($container->get(RealmProvider::class));

        return $app;
    }
}
