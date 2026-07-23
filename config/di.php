<?php

declare(strict_types=1);

use AuthServer\Controllers\Admin\MigrationsController;
use AuthServer\Controllers\AuthorizationController;
use AuthServer\Controllers\ErrorController;
use AuthServer\Controllers\LogoutController;
use AuthServer\Controllers\OidcController;
use AuthServer\Controllers\RevokeController;
use AuthServer\Controllers\TokenController;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\LoginStateMachine as ILoginStateMachine;
use AuthServer\Interfaces\RealmRepository as IRealmRepo;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\MigrationRepository;
use AuthServer\Repositories\RealmRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\TokenBlacklistRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\FilesystemKeyStore;
use AuthServer\Services\HttpSessionCookieHandler;
use AuthServer\Services\InputValidator;
use AuthServer\Services\LoginStateMachine;
use AuthServer\Services\MigrationRunner;
use AuthServer\Services\RateLimiter;
use AuthServer\Services\SecretsService;
use AuthServer\Services\SessionOrchestrator;
use AuthServer\Services\TokenService;
use AuthServer\Services\ViewRenderer;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;

$config = parse_ini_file(__DIR__ . '/../config.ini', true);
$server = $config['server'];
$ROOT = dirname(__DIR__);

$GLOBALS['sub_path'] = $server['base_path'];

return [

    // ── Config parameters ──

    'issuer' => $server['issuer'],
    'base_path' => $server['base_path'],
    'keys_root' => $ROOT . '/keys',
    'admin_api_key' => $config['admin']['api_key'] ?? '',
    'password_hashing' => $config['password_hashing'] ?? [],
    'log_settings' => $config['log'] ?? [],
    'rate_limiting' => $config['rate_limiting'] ?? [],
    'migrations_dir' => $ROOT . '/db/migrations/',

    // ── PDO (shared) ──

    \PDO::class => function () {
        $dbPath = dirname(__DIR__) . '/db/data.db';
        return new \PDO("sqlite:{$dbPath}", '', '', [
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);
    },

    // ── Logger ──

    LoggerInterface::class => function (Psr\Container\ContainerInterface $c) {
        $log = $c->get('log_settings');
        $logLevel = $log['level'] ?? 'info';
        $logger = new Logger('auth');
        if (filter_var($log['print'] ?? true, FILTER_VALIDATE_BOOLEAN)) {
            $logger->pushHandler(new StreamHandler('php://stdout', $logLevel));
        }
        if (filter_var($log['write'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
            $logger->pushHandler(new StreamHandler(
                dirname(__DIR__) . '/log/' . date('Y-m-d') . '_' . ($log['file'] ?? 'auth_server.log'),
                $logLevel
            ));
        }
        return $logger;
    },

    // ── Key store ──

    KeyStore::class => \DI\autowire(FilesystemKeyStore::class)
        ->constructorParameter('keysDir', \DI\get('keys_root')),

    // ── Token service ──

    TokenService::class => \DI\autowire()
        ->constructorParameter('issuer', \DI\get('issuer')),

    // ── Secrets service ──

    SecretsService::class => \DI\autowire()
        ->constructorParameter('config', \DI\get('password_hashing')),

    // ── Repository interface bindings ──

    IClientRepo::class => \DI\autowire(ClientRepository::class),
    ISessionRepo::class => \DI\autowire(SessionRepository::class),
    ILoginRepo::class => \DI\autowire(LoginRepository::class),
    IUserRepo::class => \DI\autowire(UserRepository::class),
    IRealmRepo::class => \DI\autowire(RealmRepository::class),
    ILoginStateMachine::class => \DI\autowire(LoginStateMachine::class),

    // ── Domain services ──

    SessionOrchestrator::class => \DI\autowire(),
    AuthenticationOrchestrator::class => \DI\autowire(),
    InputValidator::class => \DI\autowire(),
    LoginStateMachine::class => \DI\autowire(),
    RateLimiter::class => \DI\autowire(),
    MigrationRunner::class => \DI\autowire()
        ->constructorParameter('migrationsDir', \DI\get('migrations_dir')),
    MigrationRepository::class => \DI\autowire(),
    TokenBlacklistRepository::class => \DI\autowire(),

    // ── View renderer ──

    ViewRenderer::class => \DI\autowire()
        ->constructorParameter('viewsPath', $ROOT . '/src/views')
        ->constructorParameter('layoutPath', 'template.php'),

    // ── Session cookie handler ──

    SessionCookieHandler::class => \DI\autowire(HttpSessionCookieHandler::class)
        ->constructorParameter('mountPath', \DI\get('base_path'))
        ->constructorParameter('serverName', $_SERVER['SERVER_NAME'] ?? 'localhost'),

    // ── Realm provider middleware ──

    RealmProvider::class => \DI\autowire(),

    // ── Controllers ──

    AuthorizationController::class => \DI\autowire()
        ->constructorParameter('mount_path', \DI\get('base_path')),
    TokenController::class => \DI\autowire(),
    LogoutController::class => \DI\autowire(),
    OidcController::class => \DI\autowire()
        ->constructorParameter('issuer', \DI\get('issuer')),
    ErrorController::class => \DI\autowire(),
    RevokeController::class => \DI\autowire(),
    MigrationsController::class => \DI\autowire(),
];
