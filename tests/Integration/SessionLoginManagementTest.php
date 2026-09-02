<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\AuthRecordFixture;
use AuthServer\Tests\Support\TempDirTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class SessionLoginManagementTest extends TestCase
{
    use AdminApiTrait;
    use TempDirTrait;

    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const TEST_CLIENT = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const TEST_USER = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';

    private static \Slim\App $app;
    private static string $adminKey = 'test-admin-key';
    private static string $keysRoot;

    public static function setUpBeforeClass(): void
    {
        self::$keysRoot = sys_get_temp_dir() . '/auth-keys-' . getGuid();
        mkdir(self::$keysRoot);

        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::$adminKey,
            'keys_root' => self::$keysRoot,
        ]);
    }

    public static function tearDownAfterClass(): void
    {
        self::removeDir(self::$keysRoot);
    }

    // ── Sessions ──────────────────────────────────────────────

    public function testListSessionsReturnsData(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/sessions'));
        $this->assertEnvelope($data);
    }

    public function testListSessionsFilteredByRealm(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/sessions', [], [
            'realm_id' => self::TEST_REALM,
        ]));
        $this->assertEnvelope($data);
    }

    public function testDeleteSessionRemovesLoginsAndSession(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);

        $sessionId = AuthRecordFixture::createSession($pdo, self::TEST_REALM, self::TEST_USER);
        $loginId = AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, $sessionId);

        $response = $this->handle($this->adminRequest('DELETE', '/admin/sessions/' . $sessionId));
        self::assertSame(204, $response->getStatusCode());

        $loginCount = $pdo->query("SELECT COUNT(*) FROM logins WHERE session_id = '$sessionId'")->fetchColumn();
        self::assertSame(0, (int) $loginCount, 'logins should be cascade-deleted');

        $sessionCount = $pdo->query("SELECT COUNT(*) FROM sessions WHERE id = '$sessionId'")->fetchColumn();
        self::assertSame(0, (int) $sessionCount, 'session should be deleted');
    }

    public function testDeleteMissingSessionReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest('DELETE', '/admin/sessions/nonexistent'));
    }

    public function testInvalidateByUserIdRemovesAllSessionsAndLogins(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $userId = AuthRecordFixture::createUser($pdo, self::TEST_REALM, 'temp-' . getGuid() . '@example.com');

        $s1 = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);
        $s2 = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);

        AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, $s1);
        AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, $s2);

        $data = $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $userId,
        ]));

        self::assertSame(2, $data['invalidated']);

        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM sessions WHERE user_id = '$userId'")->fetchColumn());
        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM logins WHERE session_id IN ('$s1','$s2')")->fetchColumn());
    }

    public function testInvalidateByClientIdRemovesSessionsAndLogins(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $userId = AuthRecordFixture::createUser($pdo, self::TEST_REALM, 'cid-' . getGuid() . '@example.com');
        $sessionId = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);
        $loginId = AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, $sessionId);

        $data = $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'client_id' => self::TEST_CLIENT,
        ]));

        self::assertGreaterThanOrEqual(1, $data['invalidated']);
        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM sessions WHERE id = '$sessionId'")->fetchColumn());
    }

    public function testInvalidateWithoutUserOrClientReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest('POST', '/admin/sessions/invalidate', []));
    }

    public function testInvalidateWithBothUserIdAndClientIdDoesNotDoubleCount(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $userId = AuthRecordFixture::createUser($pdo, self::TEST_REALM, 'dc-' . getGuid() . '@example.com');

        $s1 = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);
        $l1 = AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, $s1);

        $data = $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $userId,
            'client_id' => self::TEST_CLIENT,
        ]));

        self::assertSame(1, $data['invalidated']);
    }

    public function testInvalidateCountsOfflineGrantsAndSessions(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $userId = AuthRecordFixture::createUser($pdo, self::TEST_REALM, 'cb-' . getGuid() . '@example.com');

        $s1 = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);
        $s2 = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $userId);

        AuthRecordFixture::createOfflineSession($pdo, self::TEST_REALM, $userId, self::TEST_CLIENT);

        $data = $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $userId,
        ]));

        // The total counts both the expired offline grant and the deleted sessions.
        self::assertSame(3, $data['invalidated']);

        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM sessions WHERE user_id = '$userId'")->fetchColumn());
        self::assertSame('EXPIRED', $pdo->query("SELECT status FROM offline_sessions WHERE user_id = '$userId'")->fetchColumn());
    }

    // ── Logins ────────────────────────────────────────────────

    public function testListLoginsReturnsData(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/logins'));
        $this->assertEnvelope($data);
    }

    public function testListLoginsFilteredByClient(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/logins', [], [
            'client_id' => self::TEST_CLIENT,
        ]));
        $this->assertEnvelope($data);
    }

    public function testDeleteLoginReturns204(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $loginId = AuthRecordFixture::createLogin($pdo, self::TEST_CLIENT, status: 'PENDING');

        $response = $this->handle($this->adminRequest('DELETE', '/admin/logins/' . $loginId));
        self::assertSame(204, $response->getStatusCode());

        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM logins WHERE id = '$loginId'")->fetchColumn());
    }

    public function testDeleteMissingLoginReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest('DELETE', '/admin/logins/nonexistent'));
    }

    // ── User deactivation ─────────────────────────────────────

    public function testDisabledUserCannotLogin(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);

        $userId = getGuid();
        $email = 'disabled-' . $userId . '@example.com';
        AuthRecordFixture::createUser($pdo, self::TEST_REALM, $email, valid: false, name: 'Disabled User');

        // First GET /auth to get a valid login_id and csrf_token
        $authRequest = $this->createRequest('GET',
            '/realms/test/protocol/openid-connect/auth',
            [],
            [
                'client_id' => 'local',
                'redirect_uri' => 'http://localhost:5173',
                'response_type' => 'code',
                'response_mode' => 'query',
                'scope' => 'openid',
                'state' => 'test',
                'nonce' => 'test',
            ]
        );
        $authResponse = $this->handle($authRequest);
        $authBody = (string) $authResponse->getBody();

        preg_match('/action="[^"]*\?q=([^"]*)"/', $authBody, $loginMatch);
        preg_match('/name="csrf_token"\s*value="([^"]*)"/', $authBody, $csrfMatch);

        self::assertNotEmpty($loginMatch[1], 'Should extract login_id');
        self::assertNotEmpty($csrfMatch[1], 'Should extract csrf_token');

        // Now try to login with disabled user
        $loginRequest = $this->createRequest('POST',
            '/realms/test/protocol/openid-connect/login-actions/authenticate?q=' . $loginMatch[1],
            [
                'email' => $email,
                'password' => 'testpass',
                'csrf_token' => $csrfMatch[1],
            ]
        );
        $loginResponse = $this->handle($loginRequest);

        $body = (string) $loginResponse->getBody();
        self::assertStringContainsString('user is disabled', $body);
    }

    public function testEnabledUserCanLogin(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);

        $email = 'enabled-' . getGuid() . '@example.com';
        AuthRecordFixture::createUser($pdo, self::TEST_REALM, $email, name: 'Enabled User');

        // First get the auth page to extract login_id and csrf_token
        $authRequest = $this->createRequest('GET',
            '/realms/test/protocol/openid-connect/auth',
            [],
            [
                'client_id' => 'local',
                'redirect_uri' => 'http://localhost:5173',
                'response_type' => 'code',
                'response_mode' => 'query',
                'scope' => 'openid',
                'state' => 'test',
                'nonce' => 'test',
            ]
        );
        $authResponse = $this->handle($authRequest);
        $authBody = (string) $authResponse->getBody();

        preg_match('/action="[^"]*\?q=([^"]*)"/', $authBody, $loginMatch);
        preg_match('/name="csrf_token"\s*value="([^"]*)"/', $authBody, $csrfMatch);

        self::assertNotEmpty($loginMatch[1], 'Should extract login_id');
        self::assertNotEmpty($csrfMatch[1], 'Should extract csrf_token');

        $loginRequest = $this->createRequest('POST',
            '/realms/test/protocol/openid-connect/login-actions/authenticate?q=' . $loginMatch[1],
            [
                'email' => $email,
                'password' => 'testpass',
                'csrf_token' => $csrfMatch[1],
            ]
        );
        $loginResponse = $this->handle($loginRequest);

        // Should get 302 redirect (successful login), not 200 with error
        self::assertSame(302, $loginResponse->getStatusCode());
    }

    // ── Realm delete with active sessions blocks ───────────────

    public function testDeleteRealmBlockedByActiveSessions(): void
    {
        $kid = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'))['kid'];
        $realm = $this->assertStatus(201, $this->adminRequest('POST', '/admin/realms', [
            'name' => 'delete-test-' . getGuid(),
            'keys_id' => $kid,
        ]));

        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'del-client-' . getGuid(),
            'realm_id' => $realm['id'],
            'uri' => 'https://del.example.com',
        ]));

        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => $realm['id'],
            'email' => 'del-' . getGuid() . '@example.com',
            'password' => 'pass',
        ]));

        // Create active session + login
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $sid = AuthRecordFixture::createSession($pdo, $realm['id'], $user['id']);
        $lid = AuthRecordFixture::createLogin($pdo, $client['id'], $sid, redirectUri: 'https://del.example.com');

        // Realm delete should be blocked (has clients/users)
        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/realms/' . $realm['id']));

        // Invalidate sessions, then delete user and client
        $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $user['id'],
        ]));
        $this->assertStatus(204, $this->adminRequest('DELETE', '/admin/users/' . $user['id']));
        $this->assertStatus(204, $this->adminRequest('DELETE', '/admin/clients/' . $client['id']));

        // Now realm delete should succeed
        $response = $this->handle($this->adminRequest('DELETE', '/admin/realms/' . $realm['id']));
        self::assertSame(204, $response->getStatusCode());
    }

    public function testDeleteUserBlockedByActiveSessions(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'sess-block-' . getGuid() . '@example.com',
            'password' => 'pass',
        ]));

        $pdo = self::$app->getContainer()->get(\PDO::class);
        $sid = AuthRecordFixture::createSession($pdo, self::TEST_REALM, $user['id']);

        // Delete should be blocked
        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/users/' . $user['id']));

        // Invalidate
        $this->assertStatus(200, $this->adminRequest('POST', '/admin/sessions/invalidate', [
            'user_id' => $user['id'],
        ]));

        // Now delete should succeed
        $response = $this->handle($this->adminRequest('DELETE', '/admin/users/' . $user['id']));
        self::assertSame(204, $response->getStatusCode());
    }

    public function testDeleteClientBlockedByActiveLogins(): void
    {
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'login-block-' . getGuid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://block.example.com',
        ]));

        $pdo = self::$app->getContainer()->get(\PDO::class);
        $lid = AuthRecordFixture::createLogin($pdo, $client['id'], redirectUri: 'https://block.example.com');

        // Delete should be blocked
        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/clients/' . $client['id']));

        // Delete the login directly
        $this->assertStatus(204, $this->adminRequest('DELETE', '/admin/logins/' . $lid));

        // Now delete should succeed
        $response = $this->handle($this->adminRequest('DELETE', '/admin/clients/' . $client['id']));
        self::assertSame(204, $response->getStatusCode());
    }
}
