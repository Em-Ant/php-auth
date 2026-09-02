<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\AuthRecordFixture;
use AuthServer\Tests\Support\TempDirTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class AdminMaintenanceTest extends TestCase
{
    use AdminApiTrait;
    use TempDirTrait;

    private const WEB_REALM = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const KC_APP_CLIENT = 'df616379-3695-4466-bcda-910fcb50bb01';
    private const LOCAL_CLIENT = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const USER_ID = '586d7bb3-d386-4b57-9e99-b2a460f20b47';

    private static \Slim\App $app;
    private static \PDO $pdo;
    private static string $adminKey = 'test-admin-key';
    private static string $keysRoot;

    public static function setUpBeforeClass(): void
    {
        self::$keysRoot = sys_get_temp_dir() . '/auth-maintenance-keys-' . getGuid();
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
        self::$pdo->exec('DELETE FROM token_blacklist');
        self::$pdo->exec('DELETE FROM offline_sessions');
        self::$pdo->exec('DELETE FROM logins');
        self::$pdo->exec('DELETE FROM sessions');
    }

    // ── Auth ──────────────────────────────────────────────

    public function testRequiresAuth(): void
    {
        $this->assertStatus(401, $this->createRequest('POST', '/admin/maintenance/cleanup'));
    }

    public function testRejectsWrongKey(): void
    {
        $this->assertStatus(401, $this->createRequest('POST', '/admin/maintenance/cleanup', [], [], 'wrong-key'));
    }

    // ── Empty cleanup ─────────────────────────────────────

    public function testCleanupReturnsZerosOnEmptyDatabase(): void
    {
        $data = $this->runCleanup();

        self::assertSame(0, $data['blacklist_purged']);
        self::assertSame(0, $data['logins_purged']);
        self::assertSame(0, $data['sessions_purged']);
        self::assertSame(0, $data['offline_sessions_purged']);
    }

    // ── Blacklist purge ───────────────────────────────────

    public function testPurgesExpiredBlacklistEntries(): void
    {
        AuthRecordFixture::createBlacklistEntry(self::$pdo, 'jti-expired-1', time() - 3600);
        AuthRecordFixture::createBlacklistEntry(self::$pdo, 'jti-expired-2', time() - 7200);
        AuthRecordFixture::createBlacklistEntry(self::$pdo, 'jti-active', time() + 3600);

        $data = $this->runCleanup();

        self::assertSame(2, $data['blacklist_purged']);

        $remaining = $this->countRows('token_blacklist');
        self::assertSame(1, $remaining);
    }

    // ── Login purge (per-status realm TTLs) ───────────────

    public function testPurgesExpiredLogins(): void
    {
        $sessionId = AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID);

        AuthRecordFixture::createLogin(self::$pdo, self::KC_APP_CLIENT, $sessionId, 'EXPIRED', createdAtAge: '-10 days');
        AuthRecordFixture::createLogin(self::$pdo, self::KC_APP_CLIENT, null, 'PENDING', createdAtAge: '-10 days');
        AuthRecordFixture::createLogin(
            self::$pdo,
            self::KC_APP_CLIENT,
            $sessionId,
            'AUTHENTICATED',
            createdAtAge: '-10 days',
            authenticatedAtAge: '-10 days'
        );
        AuthRecordFixture::createLogin(self::$pdo, self::KC_APP_CLIENT, $sessionId, 'ACTIVE', createdAtAge: '-10 days');

        $data = $this->runCleanup();

        self::assertSame(4, $data['logins_purged']);

        $remaining = $this->countRows('logins');
        self::assertSame(0, $remaining);
    }

    public function testKeepsLoginsWithinRealmTtl(): void
    {
        $sessionId = AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID);

        AuthRecordFixture::createLogin(self::$pdo, self::KC_APP_CLIENT, $sessionId, 'PENDING', createdAtAge: '-1 minute');
        AuthRecordFixture::createLogin(
            self::$pdo,
            self::KC_APP_CLIENT,
            $sessionId,
            'AUTHENTICATED',
            createdAtAge: '-1 minute',
            authenticatedAtAge: '-1 minute'
        );

        $data = $this->runCleanup();

        self::assertSame(0, $data['logins_purged']);

        $remaining = $this->countRows('logins');
        self::assertSame(2, $remaining);
    }

    // ── Session purge ─────────────────────────────────────

    public function testPurgesExpiredSessions(): void
    {
        AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID, 'EXPIRED', '-10 days');
        AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID, 'ACTIVE', '-10 days');

        $data = $this->runCleanup();

        self::assertSame(1, $data['sessions_purged']);

        $remaining = $this->countRows('sessions');
        self::assertSame(1, $remaining);
    }

    public function testKeepsExpiredSessionReferencedByRecentLoginAndPurgesTheRest(): void
    {
        AuthRecordFixture::createBlacklistEntry(self::$pdo, 'jti-expired', time() - 3600);

        $referencedSession = AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID, 'EXPIRED', '-10 days');
        AuthRecordFixture::createLogin(self::$pdo, self::KC_APP_CLIENT, $referencedSession, 'ACTIVE', createdAtAge: '-1 minute');

        $orphanSession = AuthRecordFixture::createSession(self::$pdo, self::WEB_REALM, self::USER_ID, 'EXPIRED', '-10 days');

        $data = $this->runCleanup();

        // The referenced session must survive (FK hold by a still-valid login),
        // but cleanup must not fail and everything else is purged.
        self::assertSame(1, $data['blacklist_purged']);
        self::assertSame(0, $data['logins_purged']);
        self::assertSame(1, $data['sessions_purged']);
        self::assertSame(0, $data['offline_sessions_purged']);

        self::assertSame('EXPIRED', (string) self::$pdo->query(
            "SELECT status FROM sessions WHERE id = '$referencedSession'"
        )->fetchColumn(), 'session referenced by a live login must be kept');
        self::assertSame(1, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM logins WHERE session_id = '$referencedSession'"
        )->fetchColumn(), 'recent login must be kept');
        self::assertSame(0, (int) self::$pdo->query(
            "SELECT COUNT(*) FROM sessions WHERE id = '$orphanSession'"
        )->fetchColumn(), 'unreferenced expired session must be purged');
    }

    // ── Offline session purge ─────────────────────────────

    public function testPurgesTerminalOfflineSessions(): void
    {
        AuthRecordFixture::createOfflineSession(self::$pdo, self::WEB_REALM, self::USER_ID, self::LOCAL_CLIENT, 'EXPIRED');
        AuthRecordFixture::createOfflineSession(self::$pdo, self::WEB_REALM, self::USER_ID, self::LOCAL_CLIENT, 'ACTIVE');

        $data = $this->runCleanup();

        self::assertSame(1, $data['offline_sessions_purged']);

        $remaining = $this->countRows('offline_sessions');
        self::assertSame(1, $remaining);
    }

    public function testPurgesActiveOfflineSessionsPastSlidingWindow(): void
    {
        AuthRecordFixture::createOfflineSession(
            self::$pdo,
            self::WEB_REALM,
            self::USER_ID,
            self::LOCAL_CLIENT,
            'ACTIVE',
            '-60 days',
            '-60 days'
        );

        $data = $this->runCleanup();

        self::assertSame(1, $data['offline_sessions_purged']);
    }

    public function testPurgesActiveOfflineSessionsWithNullUpdatedAt(): void
    {
        // Never-refreshed grants have no updated_at; the runtime ages them out
        // from created_at (OfflineSessionService::isExpired), so must cleanup.
        AuthRecordFixture::createOfflineSession(self::$pdo, self::WEB_REALM, self::USER_ID, self::LOCAL_CLIENT, 'ACTIVE', '-60 days');

        $data = $this->runCleanup();

        self::assertSame(1, $data['offline_sessions_purged']);

        $remaining = $this->countRows('offline_sessions');
        self::assertSame(0, $remaining);
    }

    public function testDoesNotPurgeActiveOfflineSessionsWithinWindow(): void
    {
        AuthRecordFixture::createOfflineSession(
            self::$pdo,
            self::WEB_REALM,
            self::USER_ID,
            self::LOCAL_CLIENT,
            'ACTIVE',
            '-1 hour',
            '-1 hour'
        );

        $data = $this->runCleanup();

        self::assertSame(0, $data['offline_sessions_purged']);

        $remaining = $this->countRows('offline_sessions');
        self::assertSame(1, $remaining);
    }

    // ── Idempotency ──────────────────────────────────────

    public function testCleanupIsIdempotent(): void
    {
        AuthRecordFixture::createBlacklistEntry(self::$pdo, 'jti-expired', time() - 3600);

        $data1 = $this->runCleanup();
        self::assertSame(1, $data1['blacklist_purged']);

        $data2 = $this->runCleanup();
        self::assertSame(0, $data2['blacklist_purged']);
    }

    // ── Helpers ───────────────────────────────────────────

    private function runCleanup(): array
    {
        return $this->assertStatus(200, $this->adminRequest('POST', '/admin/maintenance/cleanup'));
    }

    private function countRows(string $table): int
    {
        return (int) self::$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn();
    }

}
