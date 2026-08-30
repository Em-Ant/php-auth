<?php

declare(strict_types=1);

namespace AuthServer\Config;

use AuthServer\Controllers\Admin\ClientsController;
use AuthServer\Controllers\Admin\KeysController;
use AuthServer\Controllers\Admin\LoginsController;
use AuthServer\Controllers\Admin\MigrationsController;
use AuthServer\Controllers\Admin\OfflineSessionsController;
use AuthServer\Controllers\Admin\RealmsController;
use AuthServer\Controllers\Admin\RolesController;
use AuthServer\Controllers\Admin\ScopeRolesController;
use AuthServer\Controllers\Admin\SessionsController;
use AuthServer\Controllers\Admin\UserRolesController;
use AuthServer\Controllers\Admin\UsersController;
use AuthServer\Controllers\AuthorizationController;
use AuthServer\Controllers\ErrorController;
use AuthServer\Controllers\IntrospectController;
use AuthServer\Controllers\LogoutController;
use AuthServer\Controllers\OidcController;
use AuthServer\Controllers\RevokeController;
use AuthServer\Controllers\TokenController;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\OfflineSessionRepository as IOfflineSessionRepo;
use AuthServer\Interfaces\RealmRepository as IRealmRepo;
use AuthServer\Interfaces\RoleRepository as IRoleRepo;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\MigrationRepository;
use AuthServer\Repositories\OfflineSessionRepository;
use AuthServer\Repositories\RealmRepository;
use AuthServer\Repositories\RoleRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\TokenBlacklistRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\ActiveSessionResolver;
use AuthServer\Services\ClientAuthenticator;
use AuthServer\Services\Database;
use AuthServer\Services\FilesystemKeyStore;
use AuthServer\Services\HttpSessionCookieHandler;
use AuthServer\Services\LoginStateMachine;
use AuthServer\Services\LogoutService;
use AuthServer\Services\MigrationRunner;
use AuthServer\Services\OfflineSessionService;
use AuthServer\Services\RateLimiter;
use AuthServer\Services\RoleAdminService;
use AuthServer\Services\ScopeResolver;
use AuthServer\Services\SecretsService;
use AuthServer\Services\SessionOrchestrator;
use AuthServer\Services\TokenGrantService;
use AuthServer\Services\TokenIntrospectionService;
use AuthServer\Services\TokenRevocationService;
use AuthServer\Services\TokenService;
use AuthServer\Services\TokenValidator;
use AuthServer\Services\UserAdminService;
use AuthServer\Services\ViewRenderer;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final class Definitions
{
    public static function get(): array
    {
        $root = dirname(__DIR__, 2);
        $config = parse_ini_file($root . '/config.ini', true);
        $server = $config['server'];

        $GLOBALS['sub_path'] = $server['base_path'];
        // Ops allow-list entries are matched against the full request path, so they
        // must carry the base_path prefix (Slim only strips it for route matching).
        $adminBasePath = rtrim((string) ($server['base_path'] ?? ''), '/');

        return [

            // ── Config parameters ──

            'issuer' => $server['issuer'],
            'base_path' => $server['base_path'],
            'keys_root' => $root . '/keys',
            'admin_api_key' => $config['admin']['api_key'] ?? '',
            'admin_realm' => $config['admin']['realm'] ?? 'admin',
            'admin_allow_all' => filter_var($config['admin']['allow_all'] ?? true, FILTER_VALIDATE_BOOLEAN),
            // Ops allow-list entries are matched against the full request path, so they
            // must carry the base_path prefix (Slim only strips it for route matching).
            'admin_ops_allow_list' => array_map(
                static fn (string $prefix): string => $adminBasePath . $prefix,
                ['/admin/migrations', '/db/migrations', '/admin/maintenance']
            ),
            'password_hashing' => $config['password_hashing'] ?? [],
            'log_settings' => $config['log'] ?? [],
            'rate_limiting' => $config['rate_limiting'] ?? [],
            'migrations_dir' => $root . '/migrations/',
            'allowed_origins' => self::parseAllowedOrigins($server['allowed_origins'] ?? null),

            // ── PDO (shared) ──

            \PDO::class => function () use ($root) {
                return Database::connect("sqlite:{$root}/db/data.db");
            },

            // ── Logger ──

            LoggerInterface::class => function (ContainerInterface $c) use ($root) {
                $log = $c->get('log_settings');
                $logLevel = $log['level'] ?? 'info';
                $logger = new Logger('auth');
                if (filter_var($log['print'] ?? true, FILTER_VALIDATE_BOOLEAN)) {
                    $logger->pushHandler(new StreamHandler('php://stdout', $logLevel));
                }
                if (filter_var($log['write'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
                    $logger->pushHandler(new StreamHandler(
                        $root . '/log/' . date('Y-m-d') . '_' . ($log['file'] ?? 'auth_server.log'),
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

            // ── Token validator ──

            TokenValidator::class => \DI\autowire()
                ->constructorParameter('issuer', \DI\get('issuer')),

            // ── Secrets service ──

            SecretsService::class => \DI\autowire()
                ->constructorParameter('config', \DI\get('password_hashing')),

            // ── Repository interface bindings ──

            IClientRepo::class => \DI\autowire(ClientRepository::class),
            ISessionRepo::class => \DI\autowire(SessionRepository::class),
            ILoginRepo::class => \DI\autowire(LoginRepository::class),
            IOfflineSessionRepo::class => \DI\autowire(OfflineSessionRepository::class),
            IUserRepo::class => \DI\autowire(UserRepository::class),
            IRealmRepo::class => \DI\autowire(RealmRepository::class),
            IRoleRepo::class => \DI\autowire(RoleRepository::class),

            // ── Domain services ──

            SessionOrchestrator::class => \DI\autowire(),
            AuthenticationOrchestrator::class => \DI\autowire(),
            LogoutService::class => \DI\autowire(),
            TokenGrantService::class => \DI\autowire(),
            TokenRevocationService::class => \DI\autowire(),
            TokenIntrospectionService::class => \DI\autowire(),
            OfflineSessionService::class => \DI\autowire(),
            UserAdminService::class => \DI\autowire(),
            LoginStateMachine::class => \DI\autowire(),
            ActiveSessionResolver::class => \DI\autowire(),
            ScopeResolver::class => \DI\autowire(),
            ClientAuthenticator::class => \DI\autowire(),
            RateLimiter::class => \DI\autowire(),
            MigrationRunner::class => \DI\autowire()
                ->constructorParameter('migrationsDir', \DI\get('migrations_dir')),
            MigrationRepository::class => \DI\autowire(),
            TokenBlacklistRepository::class => \DI\autowire(),

            // ── View renderer ──

            ViewRenderer::class => \DI\autowire()
                ->constructorParameter('viewsPath', $root . '/src/views')
                ->constructorParameter('layoutPath', 'template.php'),

            // ── Session cookie handler ──

            SessionCookieHandler::class => \DI\autowire(HttpSessionCookieHandler::class)
                ->constructorParameter('mountPath', \DI\get('base_path'))
                ->constructorParameter('serverName', $_SERVER['SERVER_NAME'] ?? 'localhost'),

            // ── Realm provider middleware ──

            RealmProvider::class => \DI\autowire(),

            // ── Admin auth middleware ──

            \AuthServer\Middleware\AdminAuthMiddleware::class => \DI\autowire()
                ->constructorParameter('adminApiKey', \DI\get('admin_api_key'))
                ->constructorParameter('adminRealmName', \DI\get('admin_realm'))
                ->constructorParameter('allowAll', \DI\get('admin_allow_all'))
                ->constructorParameter('opsAllowList', \DI\get('admin_ops_allow_list')),

            // ── Controllers ──

            AuthorizationController::class => \DI\autowire()
                ->constructorParameter('mountPath', \DI\get('base_path')),
            TokenController::class => \DI\autowire(),
            LogoutController::class => \DI\autowire(),
            OidcController::class => \DI\autowire()
                ->constructorParameter('issuer', \DI\get('issuer')),
            ErrorController::class => \DI\autowire(),
            IntrospectController::class => \DI\autowire(),
            RevokeController::class => \DI\autowire(),
            MigrationsController::class => \DI\autowire(),
            RealmsController::class => \DI\autowire(),
            ClientsController::class => \DI\autowire(),
            UsersController::class => \DI\autowire(),
            SessionsController::class => \DI\autowire(),
            LoginsController::class => \DI\autowire(),
            KeysController::class => \DI\autowire()
                ->constructorParameter('keysRoot', \DI\get('keys_root')),
            \AuthServer\Controllers\Admin\OfflineSessionsController::class => \DI\autowire(),
            RolesController::class => \DI\autowire(),
            RoleAdminService::class => \DI\autowire(),
            UserRolesController::class => \DI\autowire(),
            ScopeRolesController::class => \DI\autowire(),
        ];
    }

    /**
     * Parses `allowed_origins` from `[server]` in config.ini. Absent or empty
     * yields an empty list, which CorsMiddleware treats as deny-all (no CORS
     * headers). A single '*' entry reflects any origin (dev-friendly).
     *
     * @return list<string>
     */
    private static function parseAllowedOrigins(mixed $raw): array
    {
        if (!is_string($raw)) {
            return [];
        }

        $origins = array_map(trim(...), explode(',', $raw));

        return array_values(array_filter($origins, static fn(string $o): bool => $o !== ''));
    }
}
