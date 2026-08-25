<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\get_guid;

class SessionLoginManagementTest extends TestCase
{
    use AdminApiTrait;

    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const TEST_CLIENT = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const TEST_USER = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';

    private static \Slim\App $app;
    private static string $adminKey = 'test-admin-key';

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::$adminKey,
        ]);
    }

    // ── Sessions ──────────────────────────────────────────────

    public function testListSessionsReturnsData(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/sessions'));
        self::assertArrayHasKey('sessions', $data);
    }

    public function testListSessionsFilteredByRealm(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/sessions', [], [
            'realm_id' => self::TEST_REALM,
        ]));
        self::assertArrayHasKey('sessions', $data);
    }

    public function testDeleteSessionRemovesLoginsAndSession(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);

        $sessionId = get_guid();
        $loginId = get_guid();
        $stmt = $pdo->prepare(
            "INSERT INTO sessions (id, realm_id, user_id, acr, status)
             VALUES (:id, :realm, :user, '0', 'ACTIVE')"
        );
        $stmt->execute([':id' => $sessionId, ':realm' => self::TEST_REALM, ':user' => self::TEST_USER]);

        $stmt = $pdo->prepare(
            "INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status)
             VALUES (:id, :client, :session, 'st', 'nc', 'openid', 'https://example.com', 'query', 'ACTIVE')"
        );
        $stmt->execute([':id' => $loginId, ':client' => self::TEST_CLIENT, ':session' => $sessionId]);

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
        $userId = get_guid();

        // Create a user first to satisfy FK
        $hash = password_hash('pass', PASSWORD_BCRYPT, ['cost' => 4]);
        $pdo->exec("INSERT INTO users (id, realm_id, name, email, password, valid)
                     VALUES ('$userId', '" . self::TEST_REALM . "', 'Temp', 'temp-".get_guid()."@example.com', '$hash', 'TRUE')");

        $s1 = get_guid();
        $s2 = get_guid();
        $pdo->exec("INSERT INTO sessions (id, realm_id, user_id, acr, status) VALUES ('$s1', '" . self::TEST_REALM . "', '$userId', '0', 'ACTIVE')");
        $pdo->exec("INSERT INTO sessions (id, realm_id, user_id, acr, status) VALUES ('$s2', '" . self::TEST_REALM . "', '$userId', '0', 'ACTIVE')");

        $l1 = get_guid();
        $l2 = get_guid();
        $pdo->exec("INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status) VALUES ('$l1', '" . self::TEST_CLIENT . "', '$s1', 'st', 'nc', 'openid', 'https://example.com', 'query', 'ACTIVE')");
        $pdo->exec("INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status) VALUES ('$l2', '" . self::TEST_CLIENT . "', '$s2', 'st', 'nc', 'openid', 'https://example.com', 'query', 'ACTIVE')");

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
        $userId = get_guid();
        $sessionId = get_guid();
        $loginId = get_guid();

        $hash = password_hash('pass', PASSWORD_BCRYPT, ['cost' => 4]);
        $pdo->exec("INSERT INTO users (id, realm_id, name, email, password, valid)
                     VALUES ('$userId', '" . self::TEST_REALM . "', 'Temp', 'cid-".get_guid()."@example.com', '$hash', 'TRUE')");
        $pdo->exec("INSERT INTO sessions (id, realm_id, user_id, acr, status) VALUES ('$sessionId', '" . self::TEST_REALM . "', '$userId', '0', 'ACTIVE')");
        $pdo->exec("INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status) VALUES ('$loginId', '" . self::TEST_CLIENT . "', '$sessionId', 'st', 'nc', 'openid', 'https://example.com', 'query', 'ACTIVE')");

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

    // ── Logins ────────────────────────────────────────────────

    public function testListLoginsReturnsData(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/logins'));
        self::assertArrayHasKey('logins', $data);
    }

    public function testListLoginsFilteredByClient(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/logins', [], [
            'client_id' => self::TEST_CLIENT,
        ]));
        self::assertArrayHasKey('logins', $data);
    }

    public function testDeleteLoginReturns204(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $loginId = get_guid();

        $pdo->exec("INSERT INTO logins (id, client_id, state, nonce, scope, redirect_uri, response_mode, status)
                     VALUES ('$loginId', '" . self::TEST_CLIENT . "', 'st', 'nc', 'openid', 'https://example.com', 'query', 'PENDING')");

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

        $userId = get_guid();
        $email = 'disabled-' . $userId . '@example.com';
        $hash = password_hash('testpass', PASSWORD_BCRYPT, ['cost' => 4]);
        $pdo->exec("INSERT INTO users (id, realm_id, name, email, password, valid)
                     VALUES ('$userId', '" . self::TEST_REALM . "', 'Disabled User', '$email', '$hash', 'FALSE')");

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

        $userId = get_guid();
        $email = 'enabled-' . get_guid() . '@example.com';
        $hash = password_hash('testpass', PASSWORD_BCRYPT, ['cost' => 4]);
        $pdo->exec("INSERT INTO users (id, realm_id, name, email, password, valid)
                     VALUES ('$userId', '" . self::TEST_REALM . "', 'Enabled User', '$email', '$hash', 'TRUE')");

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
            'name' => 'delete-test-' . get_guid(),
            'keys_id' => $kid,
        ]));

        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'del-client-' . get_guid(),
            'realm_id' => $realm['id'],
            'uri' => 'https://del.example.com',
        ]));

        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => $realm['id'],
            'email' => 'del-' . get_guid() . '@example.com',
            'password' => 'pass',
        ]));

        // Create active session + login
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $sid = get_guid();
        $lid = get_guid();
        $pdo->exec("INSERT INTO sessions (id, realm_id, user_id, acr, status) VALUES ('$sid', '{$realm['id']}', '{$user['id']}', '0', 'ACTIVE')");
        $pdo->exec("INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status) VALUES ('$lid', '{$client['id']}', '$sid', 'st', 'nc', 'openid', 'https://del.example.com', 'query', 'ACTIVE')");

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
            'email' => 'sess-block-' . get_guid() . '@example.com',
            'password' => 'pass',
        ]));

        $pdo = self::$app->getContainer()->get(\PDO::class);
        $sid = get_guid();
        $pdo->exec("INSERT INTO sessions (id, realm_id, user_id, acr, status) VALUES ('$sid', '" . self::TEST_REALM . "', '{$user['id']}', '0', 'ACTIVE')");

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
            'name' => 'login-block-' . get_guid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://block.example.com',
        ]));

        $pdo = self::$app->getContainer()->get(\PDO::class);
        $lid = get_guid();
        $pdo->exec("INSERT INTO logins (id, client_id, state, nonce, scope, redirect_uri, response_mode, status)
                     VALUES ('$lid', '{$client['id']}', 'st', 'nc', 'openid', 'https://block.example.com', 'query', 'ACTIVE')");

        // Delete should be blocked
        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/clients/' . $client['id']));

        // Delete the login directly
        $this->assertStatus(204, $this->adminRequest('DELETE', '/admin/logins/' . $lid));

        // Now delete should succeed
        $response = $this->handle($this->adminRequest('DELETE', '/admin/clients/' . $client['id']));
        self::assertSame(204, $response->getStatusCode());
    }
}
