<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\TokenService;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class AdminAuthMiddlewareTest extends TestCase
{
    use IntegrationFlowTrait;
    private const ADMIN_API_KEY = 'test-admin-key';
    private const ISSUER = 'http://localhost:8000';

    private static \Slim\App $app;
    private static \Slim\App $appNarrowed;
    private static \PDO $pdo;
    private static TokenService $tokenService;
    private static \AuthServer\Models\Realm $adminRealm;
    private static \AuthServer\Models\Realm $webRealm;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::ADMIN_API_KEY,
            'admin_allow_all' => true,
        ]);
        self::$pdo = self::$app->getContainer()->get(\PDO::class);
        self::$tokenService = self::$app->getContainer()->get(TokenService::class);
        $realmRepo = self::$app->getContainer()->get(\AuthServer\Interfaces\RealmRepository::class);
        $foundAdmin = $realmRepo->findByName('admin');
        self::assertNotNull($foundAdmin, 'admin realm must be seeded');
        self::$adminRealm = $foundAdmin;
        $foundWeb = $realmRepo->findByName('web');
        self::assertNotNull($foundWeb);
        self::$webRealm = $foundWeb;

        // Second app with allowAll=false to verify narrowed fallback
        self::$appNarrowed = TestAppFactory::createApp([
            'admin_api_key' => self::ADMIN_API_KEY,
            'admin_allow_all' => false,
        ]);
    }

    private function createToken(
        \AuthServer\Models\Realm $realm,
        string $clientName,
        string $sub,
        array $roles,
        int $expDelta = 300,
        string $typ = 'Bearer',
        string $scope = 'openid profile email'
    ): string {
        $now = time();
        $payload = [
            'exp' => $now + $expDelta,
            'iat' => $now,
            'jti' => getGuid(),
            'iss' => self::ISSUER . '/realms/' . $realm->getName(),
            'aud' => $clientName,
            'sub' => $sub,
            'typ' => $typ,
            'azp' => $clientName,
            'realm_access' => ['roles' => $roles],
            'scope' => $scope,
            'sid' => getGuid(),
            'preferred_username' => $sub,
        ];

        return self::$tokenService->createToken($payload, $realm->getKeysId());
    }

    private function request(string $method, string $path, ?string $auth = null, array $headers = []): \Psr\Http\Message\ServerRequestInterface
    {
        if ($auth !== null) {
            $headers['Authorization'] = 'Bearer ' . $auth;
        }

        return $this->createRequest($method, $path, headers: $headers);
    }

    private function assertResponseStatus(
        \Slim\App $app,
        string $method,
        string $path,
        ?string $auth = null,
        array $headers = [],
        int $expected = 200
    ): void {
        $resp = $app->handle($this->request($method, $path, $auth, $headers));
        self::assertSame($expected, $resp->getStatusCode(), "$method $path expected $expected");
    }

    public function testAdminJwtSucceedsOnNonOps(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'admin-user', ['admin']);
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt);
    }

    public function testAdminJwtWithOfflineScopeAlsoSucceeds(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'ci-deployer', 'admin-user', ['admin'], 300, 'Bearer', 'openid profile email offline_access');
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt);
    }

    public function testNonAdminJwtReturns401(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'basic-user', ['basic']);
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt, expected: 401);
    }

    public function testMissingRoleReturns401(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'admin-user', []);
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt, expected: 401);
    }

    public function testWrongRealmJwtReturns401(): void
    {
        $jwt = $this->createToken(self::$webRealm, 'playground', 'user1', ['admin']);
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt, expected: 401);
    }

    public function testExpiredJwtReturns401(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'admin-user', ['admin'], -10);
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt, expected: 401);
    }

    public function testTamperedJwtReturns401(): void
    {
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'admin-user', ['admin']);
        $parts = explode('.', $jwt);
        $tampered = $parts[0] . '.' . $parts[1] . '.invalidsignature';
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $tampered, expected: 401);
    }

    public function testStaticOnNonOpsSucceedsWhenAllowAllTrue(): void
    {
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', self::ADMIN_API_KEY);
    }

    public function testStaticViaXAdminKeyOnNonOpsSucceedsWhenAllowAllTrue(): void
    {
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', headers: ['X-Admin-Key' => self::ADMIN_API_KEY]);
    }

    public function testStaticOnMigrationsSucceedsWhenAllowAllTrue(): void
    {
        $this->assertResponseStatus(self::$app, 'GET', '/admin/migrations/status', self::ADMIN_API_KEY);
    }

    public function testStaticOnNonOpsFailsWhenAllowAllFalse(): void
    {
        $this->assertResponseStatus(self::$appNarrowed, 'GET', '/admin/realms', self::ADMIN_API_KEY, expected: 401);
    }

    public function testStaticViaXAdminKeyOnNonOpsFailsWhenAllowAllFalse(): void
    {
        $this->assertResponseStatus(self::$appNarrowed, 'GET', '/admin/realms', headers: ['X-Admin-Key' => self::ADMIN_API_KEY], expected: 401);
    }

    public function testStaticOnMigrationsSucceedsWhenAllowAllFalse(): void
    {
        $this->assertResponseStatus(self::$appNarrowed, 'GET', '/admin/migrations/status', self::ADMIN_API_KEY);
    }

    public function testStaticViaXAdminKeyOnMigrationsSucceedsWhenAllowAllFalse(): void
    {
        $this->assertResponseStatus(self::$appNarrowed, 'GET', '/admin/migrations/status', headers: ['X-Admin-Key' => self::ADMIN_API_KEY]);
    }

    public function testAdminUiPkceTokenCanAccessMigrations(): void
    {
        // UI uses PKCE, no offline_access, short-lived access token — same shape as admin JWT
        $jwt = $this->createToken(self::$adminRealm, 'admin-ui', 'admin-user', ['admin'], 300, 'Bearer', 'openid profile email');
        $this->assertResponseStatus(self::$app, 'GET', '/admin/migrations/status', $jwt);
    }

    public function testJwtMissingReturns401(): void
    {
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', expected: 401);
    }

    public function testWrongStaticKeyReturns401(): void
    {
        $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', 'wrong-key', expected: 401);
    }

    public function testSsoAndOfflineBothFailWhenMissingRole(): void
    {
        $sso = $this->createToken(self::$adminRealm, 'admin-ui', 'u1', ['basic'], 300, 'Bearer', 'openid profile email');
        $offline = $this->createToken(self::$adminRealm, 'ci-deployer', 'u1', ['basic'], 300, 'Bearer', 'openid profile email offline_access');
        foreach ([$sso, $offline] as $jwt) {
            $this->assertResponseStatus(self::$app, 'GET', '/admin/realms', $jwt, expected: 401);
        }
    }
}
