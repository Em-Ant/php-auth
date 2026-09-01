<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\TempDirTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class AdminAuditLogTest extends TestCase
{
    use AdminApiTrait;
    use TempDirTrait;

    private const WEB_REALM = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const KC_APP_CLIENT = 'df616379-3695-4466-bcda-910fcb50bb01';

    private static \Slim\App $app;
    private static \PDO $pdo;
    private static string $adminKey = 'test-admin-key';
    private static string $keysRoot;

    public static function setUpBeforeClass(): void
    {
        self::$keysRoot = sys_get_temp_dir() . '/auth-audit-keys-' . getGuid();
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

    protected function setUp(): void
    {
        self::$pdo->exec('DELETE FROM audit_logs');
    }

    // ── Helpers ──────────────────────────────────────────────

    private function seedAuditEntry(string $action, string $realmId): string
    {
        $id = getGuid();
        self::$pdo->prepare(
            "INSERT INTO audit_logs (id, action, actor_type, actor_id, realm_id, target_type, target_id, detail, created_at)
             VALUES (?, ?, 'api_key', NULL, ?, 'realm', NULL, NULL, ?)"
        )->execute([$id, $action, $realmId, date('Y-m-d H:i:s')]);

        return $id;
    }

    private function seedAuditEntryWithTime(string $action, string $realmId, string $createdAt): string
    {
        $id = getGuid();
        self::$pdo->prepare(
            "INSERT INTO audit_logs (id, action, actor_type, actor_id, realm_id, target_type, target_id, detail, created_at)
             VALUES (?, ?, 'api_key', NULL, ?, 'realm', NULL, NULL, ?)"
        )->execute([$id, $action, $realmId, $createdAt]);

        return $id;
    }

    private function auditCount(): int
    {
        return (int) self::$pdo->query("SELECT COUNT(*) FROM audit_logs")->fetchColumn();
    }

    // ── List ─────────────────────────────────────────────────

    public function testListReturnsEmptyWhenNoEntries(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs'));

        self::assertSame([], $data['items']);
        self::assertSame(0, $data['total']);
    }

    public function testListReturnsSeededEntries(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.update', self::TEST_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs'));

        self::assertCount(2, $data['items']);
        self::assertSame(2, $data['total']);
    }

    public function testListFiltersByAction(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.update', self::WEB_REALM);
        $this->seedAuditEntry('user.create', self::WEB_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'realm.create']));

        self::assertCount(1, $data['items']);
        self::assertSame('realm.create', $data['items'][0]['action']);
    }

    public function testListFiltersByRealmId(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.create', self::TEST_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['realm_id' => self::WEB_REALM]));

        self::assertCount(1, $data['items']);
        self::assertSame(self::WEB_REALM, $data['items'][0]['realm_id']);
    }

    public function testListFiltersByActorType(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);

        $id = getGuid();
        self::$pdo->prepare(
            "INSERT INTO audit_logs (id, action, actor_type, actor_id, realm_id, target_type, target_id, detail, created_at)
             VALUES (?, 'realm.update', 'admin_user', 'admin-sub', ?, 'realm', NULL, NULL, ?)"
        )->execute([$id, self::WEB_REALM, date('Y-m-d H:i:s')]);

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['actor_type' => 'admin_user']));

        self::assertCount(1, $data['items']);
        self::assertSame('admin_user', $data['items'][0]['actor_type']);
    }

    public function testListPaginates(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->seedAuditEntry('realm.create', self::WEB_REALM);
        }

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['limit' => 2, 'offset' => 0]));

        self::assertCount(2, $data['items']);
        self::assertSame(3, $data['total']);
        self::assertSame(2, $data['limit']);
        self::assertSame(0, $data['offset']);
    }

    // ── List date range validation ───────────────────────────

    public function testListRejectsInvalidDateRange(): void
    {
        $this->assertStatus(400, $this->adminRequest('GET', '/admin/audit-logs', [], ['from' => 'not-a-date']));
        $this->assertStatus(400, $this->adminRequest('GET', '/admin/audit-logs', [], ['to' => '2025-99-99']));
    }

    public function testListFromAndToIncludeWholeDays(): void
    {
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2026-06-15 10:00:00');

        $fromData = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['from' => '2026-06-15']));
        self::assertCount(1, $fromData['items']);

        $toData = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['to' => '2026-06-15']));
        self::assertCount(1, $toData['items']);
    }

    // ── Read ─────────────────────────────────────────────────

    public function testReadReturnsEntry(): void
    {
        $id = $this->seedAuditEntry('realm.create', self::WEB_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('GET', "/admin/audit-logs/$id"));

        self::assertSame($id, $data['id']);
        self::assertSame('realm.create', $data['action']);
        self::assertSame(self::WEB_REALM, $data['realm_id']);
    }

    public function testReadReturns404ForMissing(): void
    {
        $this->assertStatus(404, $this->adminRequest('GET', '/admin/audit-logs/nonexistent'));
    }

    // ── End-to-end: admin writes produce audit entries ───────

    public function testAdminWriteCreatesAuditEntries(): void
    {
        $created = $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => 'audit-flow@example.test',
            'password' => 'hunter2-secret',
            'name' => 'Audit Flow',
        ]));

        $createEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'user.create']));
        self::assertCount(1, $createEntries['items']);
        $entry = $createEntries['items'][0];
        self::assertSame('api_key', $entry['actor_type']);
        self::assertNull($entry['actor_id']);
        self::assertSame(self::TEST_REALM, $entry['realm_id']);
        self::assertSame('user', $entry['target_type']);
        self::assertSame($created['id'], $entry['target_id']);
        self::assertIsArray($entry['detail']);
        self::assertSame('audit-flow@example.test', $entry['detail']['email']);
        self::assertSame('***', $entry['detail']['password']);
        self::assertStringNotContainsString('hunter2-secret', (string) json_encode($entry));

        $this->assertStatus(200, $this->adminRequest('PUT', '/admin/users/' . $created['id'], ['name' => 'Renamed Flow']));

        $updateEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'user.update']));
        self::assertCount(1, $updateEntries['items']);
        self::assertSame($created['id'], $updateEntries['items'][0]['target_id']);
        self::assertSame('Renamed Flow', $updateEntries['items'][0]['detail']['name']);

        $this->assertStatus(204, $this->adminRequest('DELETE', '/admin/users/' . $created['id']));

        $deleteEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'user.delete']));
        self::assertCount(1, $deleteEntries['items']);
        self::assertSame($created['id'], $deleteEntries['items'][0]['target_id']);
    }

    public function testScopeRoleMappingWritesAuditableDetail(): void
    {
        $roleId = getGuid();
        self::$pdo->prepare('INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)')
            ->execute([$roleId, self::TEST_REALM, 'audit-role']);

        $this->assertStatus(201, $this->adminRequest(
            'POST',
            '/admin/clients/' . self::KC_APP_CLIENT . '/scope-roles',
            ['scope' => 'profile', 'role_id' => $roleId, 'required' => true]
        ));

        $createEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'scope_role.create']));
        self::assertCount(1, $createEntries['items']);
        self::assertSame(self::KC_APP_CLIENT, $createEntries['items'][0]['detail']['client_id']);
        self::assertSame('profile', $createEntries['items'][0]['detail']['scope']);

        $this->assertStatus(200, $this->adminRequest(
            'PUT',
            '/admin/clients/' . self::KC_APP_CLIENT . '/scope-roles/profile/' . $roleId,
            ['required' => false]
        ));

        $updateEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'scope_role.update']));
        self::assertCount(1, $updateEntries['items']);
        self::assertSame(self::KC_APP_CLIENT, $updateEntries['items'][0]['detail']['client_id']);
        self::assertSame('profile', $updateEntries['items'][0]['detail']['scope']);

        // The idempotent no-op delete (mapping never existed) must not be recorded.
        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            '/admin/clients/' . self::KC_APP_CLIENT . '/scope-roles/nonexistent/' . $roleId
        ));
        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            '/admin/clients/' . self::KC_APP_CLIENT . '/scope-roles/profile/' . $roleId
        ));

        $deleteEntries = $this->assertStatus(200, $this->adminRequest('GET', '/admin/audit-logs', [], ['action' => 'scope_role.delete']));
        self::assertCount(1, $deleteEntries['items']);
        self::assertSame($roleId, $deleteEntries['items'][0]['target_id']);
        self::assertSame(self::KC_APP_CLIENT, $deleteEntries['items'][0]['detail']['client_id']);
        self::assertSame('profile', $deleteEntries['items'][0]['detail']['scope']);
    }

    // ── Purge (DELETE with query params or JSON body) ────────

    public function testPurgeAcceptsJsonBody(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.update', self::WEB_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('DELETE', '/admin/audit-logs', [
            'realm_id' => self::WEB_REALM,
        ]));

        self::assertSame(2, $data['deleted']);
        self::assertSame(0, $this->auditCount());
    }

    public function testPurgeRejectsMalformedBodyValue(): void
    {
        $this->assertStatus(400, $this->adminRequest('DELETE', '/admin/audit-logs', [
            'realm_id' => 123,
        ]));
    }

    public function testPurgeByRealmId(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.create', self::WEB_REALM);
        $this->seedAuditEntry('realm.create', self::TEST_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('DELETE', '/admin/audit-logs', [], ['realm_id' => self::WEB_REALM]));

        self::assertSame(2, $data['deleted']);
        self::assertSame(1, $this->auditCount());
    }

    public function testPurgeByOlderThan(): void
    {
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2025-01-01 10:00:00');
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2025-06-15 10:00:00');
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2025-12-31 10:00:00');

        $data = $this->assertStatus(200, $this->adminRequest('DELETE', '/admin/audit-logs', [], ['older_than' => '2025-06-01']));

        self::assertSame(1, $data['deleted']);
        self::assertSame(2, $this->auditCount());
    }

    public function testPurgeRequiresAtLeastOneFilter(): void
    {
        $this->assertStatus(400, $this->adminRequest('DELETE', '/admin/audit-logs'));
    }

    public function testPurgeRejectsInvalidOlderThan(): void
    {
        $this->assertStatus(400, $this->adminRequest('DELETE', '/admin/audit-logs', [], ['older_than' => 'not-a-date']));
    }

    public function testPurgeRejectsGarbageOlderThan(): void
    {
        $this->assertStatus(400, $this->adminRequest('DELETE', '/admin/audit-logs', [], ['older_than' => '2025-13-45']));
    }

    public function testPurgeReturnsZeroWhenNothingMatches(): void
    {
        $this->seedAuditEntry('realm.create', self::WEB_REALM);

        $data = $this->assertStatus(200, $this->adminRequest('DELETE', '/admin/audit-logs', [], ['realm_id' => 'nonexistent']));

        self::assertSame(0, $data['deleted']);
        self::assertSame(1, $this->auditCount());
    }

    public function testPurgeByBothFilters(): void
    {
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2025-01-01 10:00:00');
        $this->seedAuditEntryWithTime('realm.create', self::WEB_REALM, '2025-12-31 10:00:00');
        $this->seedAuditEntryWithTime('realm.create', self::TEST_REALM, '2025-01-01 10:00:00');

        $data = $this->assertStatus(200, $this->adminRequest('DELETE', '/admin/audit-logs', [], [
            'realm_id' => self::WEB_REALM,
            'older_than' => '2025-06-01',
        ]));

        self::assertSame(1, $data['deleted']);
        self::assertSame(2, $this->auditCount());
    }

    // ── Auth ─────────────────────────────────────────────────

    public function testUnauthorizedWithoutToken(): void
    {
        $this->assertStatus(401, $this->createRequest('GET', '/admin/audit-logs'));
    }

    public function testUnauthorizedWithWrongToken(): void
    {
        $this->assertStatus(401, $this->createRequest('GET', '/admin/audit-logs', [], [], 'wrong-key'));
    }
}
