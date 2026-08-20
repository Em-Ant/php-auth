<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\SecretsService;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

use function AuthServer\get_guid;

class AdminCrudTest extends TestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const WEB_REALM = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const TEST_CLIENT = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const CLIENT_SECRET = 'plain-secret';
    private const USER_PASSWORD = 'user-password';
    private const OLD_PASSWORD = 'old-pass';
    private const NEW_PASSWORD = 'new-pass';

    private static \Slim\App $app;
    private static \PDO $pdo;
    private static string $adminKey = 'test-admin-key';
    private static string $keysRoot;

    public static function setUpBeforeClass(): void
    {
        self::$keysRoot = sys_get_temp_dir() . '/auth-keys-' . get_guid();
        mkdir(self::$keysRoot);

        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::$adminKey,
            'keys_root' => self::$keysRoot,
        ]);
        self::$pdo = self::$app->getContainer()->get(\PDO::class);
    }

    public static function tearDownAfterClass(): void
    {
        self::removeDir(self::$keysRoot);
    }

    private static function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = "$dir/$entry";
            if (is_dir($path)) {
                self::removeDir($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }

    private function createRequest(
        string $method,
        string $path,
        array $body = [],
        array $query = [],
        ?string $auth = null
    ): ServerRequestInterface {
        $uri = $path;
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);
        if (!empty($body)) {
            $request->getBody()->write(json_encode($body));
            $request->getBody()->rewind();
        }
        $request = $request->withHeader('Content-Type', 'application/json');
        if ($auth !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $auth);
        }
        return $request;
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    private function assertStatus(int $expected, ServerRequestInterface $request): array
    {
        $response = $this->handle($request);
        self::assertSame($expected, $response->getStatusCode());
        $body = (string) $response->getBody();
        return $body === '' ? [] : json_decode($body, true) ?? [];
    }

    private function adminRequest(string $method, string $path, array $body = [], array $query = []): ServerRequestInterface
    {
        return $this->createRequest($method, $path, $body, $query, self::$adminKey);
    }

    // ── Auth ──────────────────────────────────────────────────

    public function testUnauthorizedWithoutToken(): void
    {
        $request = $this->createRequest('GET', '/admin/realms');
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testUnauthorizedWithWrongToken(): void
    {
        $request = $this->createRequest('GET', '/admin/realms', [], [], 'wrong-key');
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    // ── Keys ──────────────────────────────────────────────────

    public function testGenerateKeyReturnsKid(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'));

        self::assertArrayHasKey('kid', $data);
        self::assertDirectoryExists(self::$keysRoot . '/' . $data['kid']);
        self::assertFileExists(self::$keysRoot . '/' . $data['kid'] . '/public_key.pem');
    }

    // ── Realms ────────────────────────────────────────────────

    public function testListRealmsReturnsSeededRealms(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms'));

        self::assertArrayHasKey('realms', $data);
        $names = array_column($data['realms'], 'name');
        self::assertContains('web', $names);
        self::assertContains('test', $names);
    }

    public function testCreateRealmWithGeneratedKey(): void
    {
        $kid = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'))['kid'];

        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/realms', [
            'name' => 'crud-realm',
            'keys_id' => $kid,
        ]));

        self::assertSame('crud-realm', $data['name']);
        self::assertSame($kid, $data['keys_id']);
        self::assertSame(1800, $data['refresh_token_expires_in']);
        self::assertSame('openid profile email', $data['scope']);
        self::assertArrayHasKey('id', $data);
    }

    public function testCreateRealmWithUnknownKeysIdReturns400(): void
    {
        $request = $this->adminRequest('POST', '/admin/realms', [
            'name' => 'bad-keys-realm',
            'keys_id' => 'does-not-exist',
        ]);
        $this->assertStatus(400, $request);
    }

    public function testCreateRealmDuplicateNameReturns409(): void
    {
        $request = $this->adminRequest('POST', '/admin/realms', [
            'name' => 'web',
            'keys_id' => 'does-not-exist',
        ]);
        // Duplicate name is checked before keys validation
        $this->assertStatus(409, $request);
    }

    public function testReadRealmReturnsSeedData(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms/' . self::TEST_REALM));
        self::assertSame('test', $data['name']);
    }

    public function testReadMissingRealmReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest('GET', '/admin/realms/nonexistent'));
    }

    public function testUpdateRealmPartial(): void
    {
        $kid = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'))['kid'];
        $realm = $this->assertStatus(201, $this->adminRequest('POST', '/admin/realms', [
            'name' => 'update-realm',
            'keys_id' => $kid,
        ]));

        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/realms/' . $realm['id'], [
            'access_token_expires_in' => 600,
        ]));

        self::assertSame(600, $data['access_token_expires_in']);
        self::assertSame(1800, $data['refresh_token_expires_in'], 'untouched field must stay');
        self::assertSame('update-realm', $data['name']);
    }

    public function testDeleteRealmWithChildrenReturns409(): void
    {
        // Seed realm 'test' has clients and users
        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/realms/' . self::TEST_REALM));
    }

    public function testDeleteEmptyRealmReturns204(): void
    {
        $kid = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'))['kid'];
        $realm = $this->assertStatus(201, $this->adminRequest('POST', '/admin/realms', [
            'name' => 'delete-realm',
            'keys_id' => $kid,
        ]));

        $response = $this->handle($this->adminRequest('DELETE', '/admin/realms/' . $realm['id']));
        self::assertSame(204, $response->getStatusCode());

        $this->assertStatus(404, $this->adminRequest('GET', '/admin/realms/' . $realm['id']));
    }

    // ── Clients ───────────────────────────────────────────────

    public function testCreateClientHashesSecretAndHidesIt(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'crud-app',
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://crud-app.example.com',
            'client_secret' => self::CLIENT_SECRET,
            'require_auth' => true,
        ]));

        self::assertTrue($data['has_secret']);
        self::assertArrayNotHasKey('client_secret', $data);

        $stored = self::$pdo->query(
            "SELECT client_secret FROM clients WHERE id = '" . $data['id'] . "'"
        )->fetchColumn();
        self::assertNotSame(self::CLIENT_SECRET, $stored);
        self::assertTrue((new SecretsService())->validatePassword(self::CLIENT_SECRET, $stored));
    }

    public function testCreateClientDuplicateNameAndUriReturns409(): void
    {
        $request = $this->adminRequest('POST', '/admin/clients', [
            'name' => 'local',
            'realm_id' => self::TEST_REALM,
            'uri' => 'http://localhost:5173/*',
        ]);
        $this->assertStatus(409, $request);
    }

    public function testCreateClientUnknownRealmReturns400(): void
    {
        $request = $this->adminRequest('POST', '/admin/clients', [
            'name' => 'ghost-client',
            'realm_id' => 'nonexistent',
            'uri' => 'https://ghost.example.com',
        ]);
        $this->assertStatus(400, $request);
    }

    public function testListClientsFilteredByRealm(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/clients', [], [
            'realm_id' => self::TEST_REALM,
        ]));

        self::assertArrayHasKey('clients', $data);
        self::assertGreaterThan(0, count($data['clients']));
        foreach ($data['clients'] as $client) {
            self::assertSame(self::TEST_REALM, $client['realm_id']);
        }
    }

    public function testUpdateClientPartial(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/clients/' . self::TEST_CLIENT, [
            'require_auth' => true,
        ]));

        self::assertTrue($data['require_auth']);
        self::assertSame('local', $data['name']);
        self::assertSame('http://localhost:5173/*', $data['uri']);
    }

    public function testDeleteClientWithLoginsReturns409(): void
    {
        // Create a client, then attach a login row to it
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'guarded-client',
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://guarded.example.com',
        ]));

        $loginId = get_guid();
        $stmt = self::$pdo->prepare(
            "INSERT INTO logins (id, client_id, state, nonce, scope, redirect_uri, response_mode, status)
             VALUES (:id, :client, 'st', 'nc', 'openid', :uri, 'query', 'PENDING')"
        );
        $stmt->execute([
            ':id' => $loginId,
            ':client' => $client['id'],
            ':uri' => 'https://guarded.example.com',
        ]);

        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/clients/' . $client['id']));
    }

    public function testDeleteClientWithoutLoginsReturns204(): void
    {
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'disposable-client',
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://disposable.example.com',
        ]));

        $response = $this->handle($this->adminRequest('DELETE', '/admin/clients/' . $client['id']));
        self::assertSame(204, $response->getStatusCode());
    }

    // ── Users ─────────────────────────────────────────────────

    public function testCreateUserHashesPasswordAndHidesIt(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'crud@example.com',
            'password' => self::USER_PASSWORD,
            'name' => 'crud user',
            'realm_roles' => 'basic admin',
        ]));

        self::assertSame('crud@example.com', $data['email']);
        self::assertArrayNotHasKey('password', $data);

        $stored = self::$pdo->query(
            "SELECT password FROM users WHERE id = '" . $data['id'] . "'"
        )->fetchColumn();
        self::assertNotSame(self::USER_PASSWORD, $stored);
        self::assertTrue((new SecretsService())->validatePassword(self::USER_PASSWORD, $stored));
    }

    public function testCreateUserDuplicateEmailInRealmReturns409(): void
    {
        $request = $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'test@example.com',
            'password' => self::USER_PASSWORD,
        ]);
        $this->assertStatus(409, $request);
    }

    public function testCreateUserUnknownRealmReturns400(): void
    {
        $request = $this->adminRequest('POST', '/admin/users', [
            'realm_id' => 'nonexistent',
            'email' => 'ghost@example.com',
            'password' => self::USER_PASSWORD,
        ]);
        $this->assertStatus(400, $request);
    }

    public function testListUsersFilteredByRealm(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/users', [], [
            'realm_id' => self::TEST_REALM,
        ]));

        self::assertArrayHasKey('users', $data);
        self::assertGreaterThan(0, count($data['users']));
        foreach ($data['users'] as $user) {
            self::assertSame(self::TEST_REALM, $user['realm_id']);
        }
    }

    public function testUpdateUserPasswordRehashes(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'pw-rotate@example.com',
            'password' => self::OLD_PASSWORD,
        ]));

        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'password' => self::NEW_PASSWORD,
        ]));

        self::assertSame('pw-rotate@example.com', $data['email']);

        $stored = self::$pdo->query(
            "SELECT password FROM users WHERE id = '" . $user['id'] . "'"
        )->fetchColumn();
        self::assertTrue((new SecretsService())->validatePassword(self::NEW_PASSWORD, $stored));
    }

    public function testDeleteUserWithSessionsReturns409(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'session-user@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $sessionId = get_guid();
        $stmt = self::$pdo->prepare(
            "INSERT INTO sessions (id, realm_id, user_id, acr, status)
             VALUES (:id, :realm, :user, '0', 'ACTIVE')"
        );
        $stmt->execute([
            ':id' => $sessionId,
            ':realm' => self::TEST_REALM,
            ':user' => $user['id'],
        ]);

        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/users/' . $user['id']));
    }

    public function testDeleteUserWithoutSessionsReturns204(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'lonely@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $response = $this->handle($this->adminRequest('DELETE', '/admin/users/' . $user['id']));
        self::assertSame(204, $response->getStatusCode());
    }

    // ── Offline sessions (F-02 admin integration) ───────────────

    private function insertOfflineSession(
        string $realmId,
        string $userId,
        string $clientId,
        string $status = 'ACTIVE'
    ): void {
        $stmt = self::$pdo->prepare(
            "INSERT INTO offline_sessions (id, realm_id, user_id, client_id, acr, scope, nonce, refresh_token, status)
             VALUES (:id, :realm, :user, :client, '0', 'openid offline_access', 'nc', :refresh, :status)"
        );
        $stmt->execute([
            ':id' => get_guid(),
            ':realm' => $realmId,
            ':user' => $userId,
            ':client' => $clientId,
            ':refresh' => get_guid(),
            ':status' => $status,
        ]);
    }

    public function testDeleteUserWithActiveOfflineSessionReturns409(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'offline-user-' . get_guid() . '@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/users/' . $user['id']));
    }

    public function testDeleteClientWithActiveOfflineSessionReturns409(): void
    {
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'offline-guarded-' . get_guid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://offline-guarded.example.com',
        ]));

        $this->insertOfflineSession(
            self::TEST_REALM,
            'b0aa0c22-a356-40c7-9fa2-6f973c3f614a',
            $client['id']
        );

        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/clients/' . $client['id']));
    }

    public function testInvalidateExpiresOfflineSessionsAndUnblocksDeletion(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'offline-inv-' . get_guid() . '@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        $data = $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $user['id'],
        ]));
        self::assertSame(1, $data['invalidated']);

        $status = self::$pdo->query(
            "SELECT status FROM offline_sessions WHERE user_id = '" . $user['id'] . "'"
        )->fetchColumn();
        self::assertSame('EXPIRED', $status);

        // Expired offline grants no longer block deletion, and the delete
        // removes the rows so no orphans survive the user
        $response = $this->handle($this->adminRequest('DELETE', '/admin/users/' . $user['id']));
        self::assertSame(204, $response->getStatusCode());
        self::assertSame(
            0,
            (int) self::$pdo->query(
                "SELECT COUNT(*) FROM offline_sessions WHERE user_id = '" . $user['id'] . "'"
            )->fetchColumn()
        );
    }
}
