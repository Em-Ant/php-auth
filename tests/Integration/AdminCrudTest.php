<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\SecretsService;
use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\AuthRecordFixture;
use AuthServer\Tests\Support\TempDirTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class AdminCrudTest extends TestCase
{
    use AdminApiTrait;
    use TempDirTrait;

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
        self::$keysRoot = sys_get_temp_dir() . '/auth-keys-' . getGuid();
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

        $stored = $this->storedClientSecret($data['id']);
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
        $data = $this->adminListByTestRealm('/admin/clients');

        $items = $this->assertEnvelope($data);

        self::assertGreaterThan(0, count($items));
        foreach ($items as $client) {
            self::assertSame(self::TEST_REALM, $client['realm_id']);
        }
    }

    private function adminListByTestRealm(string $path): array
    {
        return $this->assertStatus(200, $this->adminRequest('GET', $path, [], [
            'realm_id' => self::TEST_REALM,
        ]));
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

    public function testUpdateClientRotatesSecret(): void
    {
        $client = $this->confidentialTestClient();

        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'client_secret' => 'second-secret',
        ]));

        self::assertTrue($data['has_secret']);
        self::assertArrayNotHasKey('client_secret', $data);

        $stored = $this->storedClientSecret($client['id']);
        self::assertTrue((new SecretsService())->validatePassword('second-secret', $stored));
        self::assertFalse((new SecretsService())->validatePassword(self::CLIENT_SECRET, $stored));
    }

    public function testUpdateClientPromotesToConfidentialWithSecret(): void
    {
        $client = $this->createTestClient();

        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'require_auth' => true,
            'client_secret' => self::CLIENT_SECRET,
        ]));

        self::assertTrue($data['require_auth']);
        self::assertTrue($data['has_secret']);
    }

    public function testUpdatePublicClientToConfidentialWithoutSecretReturns409(): void
    {
        $client = $this->createTestClient();

        $this->assertStatus(409, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'require_auth' => true,
        ]));
    }

    public function testUpdateClientDemotionClearsSecret(): void
    {
        $client = $this->confidentialTestClient();

        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'require_auth' => false,
        ]));

        self::assertFalse($data['require_auth']);
        self::assertFalse($data['has_secret']);
        self::assertNull($this->storedClientSecret($client['id']));
    }

    public function testUpdatePublicClientWithSecretReturns409(): void
    {
        $client = $this->createTestClient();

        $this->assertStatus(409, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'client_secret' => self::CLIENT_SECRET,
        ]));

        self::assertFalse((bool) self::$pdo->query(
            "SELECT client_secret IS NOT NULL FROM clients WHERE id = '" . $client['id'] . "'"
        )->fetchColumn());
    }

    /**
     * Creates a client in the test realm with unique name/uri defaults;
     * $overrides replace or add body fields.
     */
    private function createTestClient(array $overrides = []): array
    {
        $body = array_merge([
            'name' => 'client-' . getGuid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://' . getGuid() . '.example.com',
        ], $overrides);

        return $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', $body));
    }

    /**
     * A confidential test client: require_auth plus a known secret.
     */
    private function confidentialTestClient(): array
    {
        return $this->createTestClient([
            'client_secret' => self::CLIENT_SECRET,
            'require_auth' => true,
        ]);
    }

    /**
     * Reads back the stored (hashed) client secret directly from the DB.
     */
    private function storedClientSecret(string $clientId): string|null
    {
        $value = self::$pdo->query(
            "SELECT client_secret FROM clients WHERE id = '" . $clientId . "'"
        )->fetchColumn();

        return is_string($value) ? $value : null;
    }

    public function testCreateConfidentialClientWithoutSecretReturns409(): void
    {
        $this->assertStatus(409, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'nosecret-' . getGuid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://nosecret.example.com',
            'require_auth' => true,
        ]));
    }

    public function testCreatePublicClientWithSecretReturns409(): void
    {
        $this->assertStatus(409, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'pubnew-' . getGuid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://pubnew.example.com',
            'client_secret' => self::CLIENT_SECRET,
        ]));
    }

    public function testCreateConfidentialClientWithEmptySecretReturns409(): void
    {
        // The invariant runs on the raw value before hashing, so an empty
        // secret surfaces as 409 — same as the update path — and nothing is
        // persisted.
        $name = 'emptysecret-' . getGuid();
        $this->assertStatus(409, $this->adminRequest('POST', '/admin/clients', [
            'name' => $name,
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://emptysecret.example.com',
            'require_auth' => true,
            'client_secret' => '',
        ]));

        self::assertSame(0, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM clients WHERE name = '" . $name . "'"
        )->fetchColumn());
    }

    public function testUpdateClientWithMalformedRequireAuthReturns400AndKeepsSecret(): void
    {
        $client = $this->createTestClient([
            'client_secret' => self::CLIENT_SECRET,
            'require_auth' => true,
        ]);

        // A garbage boolean must be rejected (400), not coerced to false —
        // coercion would hit the demotion branch and wipe the stored secret.
        $this->assertStatus(400, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'require_auth' => 'treu',
        ]));

        $stored = $this->storedClientSecret($client['id']);
        self::assertNotNull($stored);
        self::assertTrue((new SecretsService())->validatePassword(self::CLIENT_SECRET, $stored));
    }

    public function testCreateClientWithMalformedRequireAuthReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'badbool-' . getGuid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://' . getGuid() . '.example.com',
            'require_auth' => 'treu',
            'client_secret' => self::CLIENT_SECRET,
        ]));
    }

    public function testPromoteConfidentialWithLegacyEmptySecretHashReturns409(): void
    {
        $client = $this->createTestClient();

        // Legacy row: empty-string hash counts as "no secret", so promoting
        // it to confidential must demand a real secret instead of leaving a
        // client that can never authenticate.
        self::$pdo->exec(
            "UPDATE clients SET client_secret = '' WHERE id = '" . $client['id'] . "'"
        );

        $this->assertStatus(409, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'require_auth' => true,
        ]));
    }

    public function testUpdatePublicClientWithEmptySecretReturns409(): void
    {
        $client = $this->createTestClient();

        // An empty secret on a public client is an invariant violation (409),
        // not a value error (400) — the checks run before any hashing.
        $this->assertStatus(409, $this->adminRequest('PUT', '/admin/clients/' . $client['id'], [
            'client_secret' => '',
        ]));
    }

    public function testCreateUserWithMalformedValidReturns400(): void
    {
        // A coerced typo would silently disable the account; it must be a 400.
        $this->assertStatus(400, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'badbool-' . getGuid() . '@example.com',
            'password' => self::USER_PASSWORD,
            'valid' => 'ture',
        ]));
    }

    public function testUpdateUserWithMalformedEmailVerifiedReturns400(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'badbool-upd-' . getGuid() . '@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->assertStatus(400, $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'email_verified' => 'yes',
        ]));

        // The rejection is total: nothing else in the request was applied.
        $stored = self::$pdo->query(
            "SELECT name FROM users WHERE id = '" . $user['id'] . "'"
        )->fetchColumn();
        self::assertSame('', $stored, 'co-issued fields must not be applied when validation fails');
    }

    public function testDeleteClientWithLoginsReturns409(): void
    {
        // Create a client, then attach a login row to it
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'guarded-client',
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://guarded.example.com',
        ]));

        $loginId = AuthRecordFixture::createLogin(
            self::$pdo,
            $client['id'],
            status: 'PENDING',
            redirectUri: 'https://guarded.example.com'
        );

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

    public function testCreateUserRejectsRemovedRealmRolesField(): void
    {
        $request = $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'stale-roles@example.com',
            'password' => self::USER_PASSWORD,
            'realm_roles' => 'basic',
        ]);
        $this->assertStatus(400, $request);
    }

    public function testUpdateUserRejectsRemovedRealmRolesField(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'stale-roles-update@example.com',
            'password' => self::USER_PASSWORD,
            'name' => 'stale roles update',
        ]));

        $request = $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'name' => 'renamed',
            'realm_roles' => 'admin',
        ]);
        $this->assertStatus(400, $request);
    }

    public function testUpdateUserRejectsRealmChange(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'realm-move@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $request = $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'realm_id' => self::WEB_REALM,
        ]);
        $this->assertStatus(400, $request);
    }

    public function testListUsersFilteredByRealm(): void
    {
        $data = $this->adminListByTestRealm('/admin/users');

        $items = $this->assertEnvelope($data);

        self::assertGreaterThan(0, count($items));
        foreach ($items as $user) {
            self::assertSame(self::TEST_REALM, $user['realm_id']);
        }
    }

    public function testListUsersPaginatesWithinSameTotal(): void
    {
        foreach ([1, 2] as $n) {
            $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
                'realm_id' => self::TEST_REALM,
                'email' => 'paged-' . getGuid() . "@example.com",
                'password' => self::USER_PASSWORD,
            ]));
        }

        $page1 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/users', [], [
            'realm_id' => self::TEST_REALM,
            'limit' => 1,
            'offset' => 0,
        ]));
        $page2 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/users', [], [
            'realm_id' => self::TEST_REALM,
            'limit' => 1,
            'offset' => 1,
        ]));

        self::assertCount(1, $page1['items']);
        self::assertCount(1, $page2['items']);
        self::assertNotSame($page1['items'][0]['id'], $page2['items'][0]['id']);
        self::assertSame(
            $page1['total'],
            $page2['total'],
            'total must be independent of limit/offset'
        );
        self::assertGreaterThanOrEqual(2, $page1['total']);
    }

    public function testListUsersInvalidPaginationFallsBackToDefaults(): void
    {
        $invalidLimits = ['abc', '-5', '0', '201'];

        foreach ($invalidLimits as $invalid) {
            $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/users', [], [
                'limit' => $invalid,
            ]));
            self::assertSame(50, $data['limit'], "invalid limit '$invalid' should fall back to default");
            self::assertSame(0, $data['offset']);
        }

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/users', [], [
            'offset' => -3,
        ]));
        self::assertSame(0, $data['offset'], 'negative offset should fall back to default');
    }

    public function testUpdateUserPasswordRehashes(): void
    {
        $user = $this->createPasswordUser('pw-rotate');

        $this->rotateUserPassword($user['id']);

        $this->assertStoredUserPassword($user['id'], self::NEW_PASSWORD);
    }

    public function testUpdateUserPasswordRevokesSessionsAndOfflineGrants(): void
    {
        $user = $this->createPasswordUser('pw-revoke');

        $sessionId = $this->insertActiveSession(self::TEST_REALM, $user['id']);

        AuthRecordFixture::createLogin(
            self::$pdo,
            self::TEST_CLIENT,
            $sessionId,
            status: 'AUTHENTICATED',
            redirectUri: 'https://rp.example.com/cb'
        );

        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        $this->rotateUserPassword($user['id']);

        self::assertSame(0, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM sessions WHERE user_id = '" . $user['id'] . "'"
        )->fetchColumn());
        self::assertSame(0, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM logins WHERE session_id = '$sessionId'"
        )->fetchColumn());
        $this->assertOfflineSessionExpired($user['id']);
    }

    public function testUpdateUserPasswordExpiresOfflineGrantsWhenUserHasNoSessions(): void
    {
        $user = $this->createPasswordUser('pw-offline');

        // No sessions at all — only an offline refresh grant. The rotation
        // must still expire the grant instead of assuming sessions exist.
        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        $this->rotateUserPassword($user['id']);

        $this->assertOfflineSessionExpired($user['id']);
    }

    public function testUpdateUserWithoutPasswordKeepsSessions(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'pw-keep-' . getGuid() . '@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->insertActiveSession(self::TEST_REALM, $user['id']);

        $this->assertStatus(200, $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'name' => 'renamed-only',
        ]));

        self::assertSame(1, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM sessions WHERE user_id = '" . $user['id'] . "'"
        )->fetchColumn());
    }

    public function testUpdateUserWithNullPasswordDoesNotRotate(): void
    {
        $user = $this->createPasswordUser('pw-null');

        $sessionId = $this->insertActiveSession(self::TEST_REALM, $user['id']);
        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        // A null password is "no password submitted": the update applies,
        // but sessions and offline grants are left alone.
        $data = $this->assertStatus(200, $this->adminRequest('PUT', '/admin/users/' . $user['id'], [
            'name' => 'renamed-with-null-pw',
            'password' => null,
        ]));
        self::assertSame('renamed-with-null-pw', $data['name']);

        $this->assertStoredUserPassword($user['id'], self::OLD_PASSWORD);

        self::assertSame(1, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM sessions WHERE id = '$sessionId'"
        )->fetchColumn());
        self::assertSame('ACTIVE', self::$pdo->query(
            "SELECT status FROM offline_sessions WHERE user_id = '" . $user['id'] . "'"
        )->fetchColumn());
    }

    public function testDeleteUserWithSessionsReturns409(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'session-user@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->insertActiveSession(self::TEST_REALM, $user['id']);

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

    /**
     * Inserts an ACTIVE session row for the user and returns its id.
     */
    private function insertActiveSession(string $realmId, string $userId): string
    {
        return AuthRecordFixture::createSession(self::$pdo, $realmId, $userId);
    }

    /**
     * Creates a user in the test realm with the OLD_PASSWORD fixture and
     * returns the created user array.
     */
    private function createPasswordUser(string $emailPrefix): array
    {
        return $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => $emailPrefix . getGuid() . '@example.com',
            'password' => self::OLD_PASSWORD,
        ]));
    }

    /**
     * Rotates the user's password via the admin API (the rotation path also
     * revokes sessions and expires offline grants).
     */
    private function rotateUserPassword(string $userId): void
    {
        $this->assertStatus(200, $this->adminRequest('PUT', '/admin/users/' . $userId, [
            'password' => self::NEW_PASSWORD,
        ]));
    }

    private function assertStoredUserPassword(string $userId, string $plain): void
    {
        $stored = self::$pdo->query(
            "SELECT password FROM users WHERE id = '" . $userId . "'"
        )->fetchColumn();
        self::assertTrue((new SecretsService())->validatePassword($plain, $stored));
    }

    private function assertOfflineSessionExpired(string $userId): void
    {
        self::assertSame('EXPIRED', self::$pdo->query(
            "SELECT status FROM offline_sessions WHERE user_id = '" . $userId . "'"
        )->fetchColumn());
    }

    private function insertOfflineSession(
        string $realmId,
        string $userId,
        string $clientId,
        string $status = 'ACTIVE'
    ): void {
        AuthRecordFixture::createOfflineSession(self::$pdo, $realmId, $userId, $clientId, $status);
    }

    public function testDeleteUserWithActiveOfflineSessionReturns409(): void
    {
        $user = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'offline-user-' . getGuid() . '@example.com',
            'password' => self::USER_PASSWORD,
        ]));

        $this->insertOfflineSession(self::TEST_REALM, $user['id'], self::TEST_CLIENT);

        $this->assertStatus(409, $this->adminRequest('DELETE', '/admin/users/' . $user['id']));
    }

    public function testDeleteClientWithActiveOfflineSessionReturns409(): void
    {
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => 'offline-guarded-' . getGuid(),
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
            'email' => 'offline-inv-' . getGuid() . '@example.com',
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
