<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function AuthServer\get_guid;

class AdminOfflineSessionsTest extends TestCase
{
    use IntegrationFlowTrait;

    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const TEST_CLIENT_A = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const TEST_USER = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';

    private static \Slim\App $app;
    private static string $adminKey = 'test-admin-key';

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::$adminKey,
        ]);
    }

    private function adminRequest(
        string $method,
        string $path,
        array $query = [],
        ?array $jsonBody = null
    ): ServerRequestInterface {
        $headers = ['Authorization' => 'Bearer ' . self::$adminKey];
        $body = null;
        if ($jsonBody !== null) {
            $body = json_encode($jsonBody);
            $headers['Content-Type'] = 'application/json';
        }

        return $this->createRequest($method, $path, $query, $body, $headers);
    }

    private function seedClient(): string
    {
        $client = $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [], [
            'name' => 'offline-sessions-client-' . get_guid(),
            'realm_id' => self::TEST_REALM,
            'uri' => 'https://offline-sessions.example.com',
            'require_auth' => false,
        ]));

        return $client['id'];
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

    private function seedOfflineSession(string $clientId, string $refreshToken): string
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $id = get_guid();

        $stmt = $pdo->prepare(
            "INSERT INTO offline_sessions (id, realm_id, user_id, client_id, acr, scope, nonce, refresh_token, status)
             VALUES (:id, :realm, :user, :client, '0', 'openid offline_access', 'nc', :refresh, 'ACTIVE')"
        );
        $stmt->execute([
            ':id' => $id,
            ':realm' => self::TEST_REALM,
            ':user' => self::TEST_USER,
            ':client' => $clientId,
            ':refresh' => $refreshToken,
        ]);

        return $id;
    }

    public function testListReturnsPaginatedEnvelope(): void
    {
        $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-env-' . get_guid());

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions'));

        self::assertArrayHasKey('items', $data);
        self::assertArrayHasKey('total', $data);
        self::assertSame(50, $data['limit']);
        self::assertSame(0, $data['offset']);
        self::assertSame(count($data['items']), $data['total']);
    }

    public function testListFilteredByClientReturnsOnlyMatchingRows(): void
    {
        $idA = $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-a-' . get_guid());
        $otherClientId = $this->seedClient();
        $this->seedOfflineSession($otherClientId, 'rt-b-' . get_guid());

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions', [
            'client_id' => self::TEST_CLIENT_A,
        ]));

        $ids = array_column($data['items'], 'id');
        self::assertContains($idA, $ids);
        foreach ($data['items'] as $item) {
            self::assertSame(self::TEST_CLIENT_A, $item['client_id']);
        }
        self::assertSame(count($ids), $data['total']);
    }

    public function testListCombinedRealmAndUserFilters(): void
    {
        $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-c-' . get_guid());

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions', [
            'realm_id' => self::TEST_REALM,
            'user_id' => self::TEST_USER,
        ]));

        self::assertGreaterThanOrEqual(1, $data['total']);
        foreach ($data['items'] as $item) {
            self::assertSame(self::TEST_REALM, $item['realm_id']);
            self::assertSame(self::TEST_USER, $item['user_id']);
        }
    }

    public function testListPaginationLimitAndOffset(): void
    {
        $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-p1-' . get_guid());
        $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-p2-' . get_guid());

        $page1 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions', [
            'client_id' => self::TEST_CLIENT_A,
            'limit' => 1,
            'offset' => 0,
        ]));
        $page2 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions', [
            'client_id' => self::TEST_CLIENT_A,
            'limit' => 1,
            'offset' => 1,
        ]));

        self::assertSame(1, count($page1['items']));
        self::assertSame(1, count($page2['items']));
        self::assertSame(1, $page1['limit']);
        self::assertSame(1, $page2['offset']);
        self::assertNotSame($page1['items'][0]['id'], $page2['items'][0]['id']);
        self::assertGreaterThanOrEqual(2, $page1['total']);
    }

    public function testListInvalidLimitFallsBackToDefault(): void
    {
        foreach (['abc', '0', '-5', '1000'] as $invalid) {
            $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions', [
                'limit' => $invalid,
            ]));
            self::assertSame(50, $data['limit'], "invalid limit '$invalid' should fall back to default");
        }
    }

    public function testReadSingleOmitsSecretFields(): void
    {
        $id = $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-read-' . get_guid());

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/offline-sessions/' . $id));

        self::assertSame($id, $data['id']);
        self::assertSame('ACTIVE', $data['status']);
        self::assertArrayNotHasKey('refresh_token', $data);
        self::assertArrayNotHasKey('nonce', $data);
    }

    public function testReadMissingReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest('GET', '/admin/offline-sessions/nonexistent'));
    }

    public function testDeleteExpiresOnlyTargetedSessionAndIsIdempotent(): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $idA = $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-del-a-' . get_guid());
        $siblingId = $this->seedOfflineSession(self::TEST_CLIENT_A, 'rt-del-b-' . get_guid());

        $response = $this->handle($this->adminRequest('DELETE', '/admin/offline-sessions/' . $idA));
        self::assertSame(204, $response->getStatusCode());

        $statusA = $pdo->query("SELECT status FROM offline_sessions WHERE id = '$idA'")->fetchColumn();
        $statusSibling = $pdo->query("SELECT status FROM offline_sessions WHERE id = '$siblingId'")->fetchColumn();
        self::assertSame('EXPIRED', $statusA);
        self::assertSame('ACTIVE', $statusSibling, 'sibling grant must stay ACTIVE');

        // Second delete is idempotent — row exists but already expired
        $second = $this->handle($this->adminRequest('DELETE', '/admin/offline-sessions/' . $idA));
        self::assertSame(204, $second->getStatusCode());
    }

    public function testDeleteMissingReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest('DELETE', '/admin/offline-sessions/nonexistent'));
    }

    public function testEndpointsRequireAdminAuth(): void
    {
        // No Authorization header — trait createRequest sends none by default
        $this->assertStatus(401, $this->createRequest('GET', '/admin/offline-sessions'));
        $this->assertStatus(401, $this->createRequest('GET', '/admin/offline-sessions/some-id'));
        $this->assertStatus(401, $this->createRequest('DELETE', '/admin/offline-sessions/some-id'));
    }
}
