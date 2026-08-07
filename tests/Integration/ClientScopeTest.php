<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class ClientScopeTest extends TestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const RESTRICTED_CLIENT_ID = 'a1b2c3d4-e5f6-4a5b-9c8d-7e6f5a4b3c2d';

    private static \Slim\App $app;
    private static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
        self::$pdo = self::$app->getContainer()->get(\PDO::class);

        // Client with an explicit scope allow-list in realm 'test'
        $stmt = self::$pdo->prepare(
            "INSERT INTO clients (id, name, realm_id, client_secret, uri, require_auth, scope)
             VALUES (:id, :name, :realm, NULL, :uri, 0, :scope)"
        );
        $stmt->execute([
            ':id' => self::RESTRICTED_CLIENT_ID,
            ':name' => 'restricted',
            ':realm' => self::TEST_REALM,
            ':uri' => 'http://localhost:5173',
            ':scope' => 'openid profile',
        ]);
    }

    private function createRequest(string $method, string $path, array $query = [], mixed $body = null): ServerRequestInterface
    {
        $uri = $path;
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);

        if ($body !== null) {
            $request->getBody()->write(http_build_query($body));
            $request->getBody()->rewind();
            $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        }

        return $request;
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    private function authRequest(string $clientId, string $scope): ResponseInterface
    {
        $request = $this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/auth',
            [
                'client_id' => $clientId,
                'redirect_uri' => 'http://localhost:5173',
                'response_type' => 'code',
                'response_mode' => 'query',
                'scope' => $scope,
                'state' => 'st',
                'nonce' => 'nc',
            ]
        );
        return $this->handle($request);
    }

    private function grantClientCredentials(string $clientId, ?string $scope = null): array
    {
        $params = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
        ];
        if ($scope !== null) {
            $params['scope'] = $scope;
        }

        $request = $this->createRequest(
            'POST',
            '/realms/test/protocol/openid-connect/token',
            [],
            $params
        );
        $response = $this->handle($request);
        return [$response, json_decode((string) $response->getBody(), true)];
    }

    // ── Auth code flow ─────────────────────────────────────────

    public function testAuthRejectsScopeNotInClientAllowList(): void
    {
        $response = $this->authRequest('restricted', 'openid email');
        self::assertSame(400, $response->getStatusCode());
    }

    public function testAuthAllowsScopeInClientAllowList(): void
    {
        $response = $this->authRequest('restricted', 'openid profile');
        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('login', (string) $response->getBody());
    }

    public function testAuthNullScopeClientInheritsRealmScope(): void
    {
        $response = $this->authRequest('local', 'openid email');
        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('login', (string) $response->getBody());
    }

    public function testAuthRejectsOfflineAccessNotInClientAllowList(): void
    {
        $response = $this->authRequest('restricted', 'openid offline_access');
        self::assertSame(400, $response->getStatusCode());
    }

    // ── Client credentials flow ────────────────────────────────

    public function testClientCredentialsRejectsScopeNotInClientAllowList(): void
    {
        [$response] = $this->grantClientCredentials('restricted', 'openid email');
        self::assertSame(400, $response->getStatusCode());
    }

    public function testClientCredentialsGrantsScopeInClientAllowList(): void
    {
        [$response, $body] = $this->grantClientCredentials('restricted', 'openid profile');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('openid profile', $body['scope']);
    }

    public function testClientCredentialsEmptyScopeGrantsClientScope(): void
    {
        [$response, $body] = $this->grantClientCredentials('restricted');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('openid profile', $body['scope']);
    }

    public function testClientCredentialsRejectsOfflineAccessNotInClientAllowList(): void
    {
        [$response] = $this->grantClientCredentials('restricted', 'openid offline_access');
        self::assertSame(400, $response->getStatusCode());
    }

    public function testClientCredentialsNullScopeClientStillGrantsRealmScope(): void
    {
        [$response, $body] = $this->grantClientCredentials('local');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('openid profile email', $body['scope']);
    }
}
