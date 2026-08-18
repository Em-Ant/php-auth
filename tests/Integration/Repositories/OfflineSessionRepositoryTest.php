<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\OfflineSession;
use AuthServer\Models\OfflineSessionStatus;
use AuthServer\Repositories\OfflineSessionRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

class OfflineSessionRepositoryTest extends RepositoryTestCase
{
    private const TEST_REALM_ID = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const OTHER_REALM_ID = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const TEST_USER_ID = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';
    private const TEST_CLIENT_ID = 'a540c566-dfbf-430a-9941-fb8531c022d4';

    private OfflineSessionRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new OfflineSessionRepository(self::$pdo);
        // RepositoryTestCase shares one in-memory DB across methods
        self::$pdo->exec('DELETE FROM offline_sessions');
    }

    private function createSession(string $id = 'off-1', ?string $storedRefresh = 'rt-1'): OfflineSession
    {
        $session = new OfflineSession(
            $id,
            self::TEST_REALM_ID,
            self::TEST_USER_ID,
            self::TEST_CLIENT_ID,
            'openid offline_access',
            null,
            '0',
            'nonce-1',
            '2025-01-01 00:00:00',
            null,
            $storedRefresh
        );
        return $this->repo->create($session);
    }

    public function testCreatePersistsAndReloads(): void
    {
        $created = $this->createSession();

        self::assertSame('off-1', $created->getId());
        self::assertSame(OfflineSessionStatus::Active, $created->getStatus());
        self::assertSame('openid offline_access', $created->getScope());
        self::assertSame(self::TEST_CLIENT_ID, $created->getClientId());

        $found = $this->repo->findById('off-1');
        self::assertNotNull($found);
        self::assertSame('off-1', $found->getId());
        self::assertSame('rt-1', $found->getRefreshToken());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testFindByRefreshToken(): void
    {
        $this->createSession();

        $found = $this->repo->findByRefreshToken('rt-1', self::TEST_REALM_ID);
        self::assertNotNull($found);
        self::assertSame('off-1', $found->getId());
    }

    public function testFindByRefreshTokenReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByRefreshToken('bogus', self::TEST_REALM_ID));
    }

    public function testFindByRefreshTokenScopedToRealm(): void
    {
        $this->createSession();

        self::assertSame(
            'off-1',
            $this->repo->findByRefreshToken('rt-1', self::TEST_REALM_ID)?->getId()
        );
        self::assertNull($this->repo->findByRefreshToken('rt-1', self::OTHER_REALM_ID));
    }

    public function testRefreshRotatesTokenAndBumpsUpdatedAt(): void
    {
        $this->createSession();

        $ok = $this->repo->refresh('off-1', 'rt-2');
        self::assertTrue($ok);

        $updated = $this->repo->findById('off-1');
        self::assertSame('rt-2', $updated->getRefreshToken());
        self::assertNotNull($updated->getUpdatedAt());

        // The rotated token is the one that resolves, the old one is gone
        self::assertNotNull($this->repo->findByRefreshToken('rt-2', self::TEST_REALM_ID));
        self::assertNull($this->repo->findByRefreshToken('rt-1', self::TEST_REALM_ID));
    }

    public function testSetExpired(): void
    {
        $this->createSession();

        $ok = $this->repo->setExpired('off-1');
        self::assertTrue($ok);

        $updated = $this->repo->findById('off-1');
        self::assertSame(OfflineSessionStatus::Expired, $updated->getStatus());
    }

    public function testCountActiveByUserId(): void
    {
        $this->createSession('off-a');
        $this->createSession('off-b', 'rt-b');

        self::assertSame(2, $this->repo->countActiveByUserId(self::TEST_USER_ID));
        self::assertSame(0, $this->repo->countActiveByUserId('other-user'));

        $this->repo->setExpired('off-a');
        self::assertSame(1, $this->repo->countActiveByUserId(self::TEST_USER_ID));
    }

    public function testCountActiveByClientId(): void
    {
        $this->createSession('off-c');

        self::assertSame(1, $this->repo->countActiveByClientId(self::TEST_CLIENT_ID));
        self::assertSame(0, $this->repo->countActiveByClientId('other-client'));
    }

    public function testSetExpiredByUserId(): void
    {
        $this->createSession('off-d');

        $count = $this->repo->setExpiredByUserId(self::TEST_USER_ID);
        self::assertSame(1, $count);
        self::assertSame(OfflineSessionStatus::Expired, $this->repo->findById('off-d')?->getStatus());

        // Idempotent: already-expired rows are not counted again
        self::assertSame(0, $this->repo->setExpiredByUserId(self::TEST_USER_ID));
    }

    public function testSetExpiredByClientId(): void
    {
        $this->createSession('off-e');

        $count = $this->repo->setExpiredByClientId(self::TEST_CLIENT_ID);
        self::assertSame(1, $count);
        self::assertSame(OfflineSessionStatus::Expired, $this->repo->findById('off-e')?->getStatus());
    }

    public function testDeleteByUserId(): void
    {
        $this->createSession('off-f');
        $this->createSession('off-g', 'rt-g');

        $count = $this->repo->deleteByUserId(self::TEST_USER_ID);
        self::assertSame(2, $count);
        self::assertNull($this->repo->findById('off-f'));
        self::assertNull($this->repo->findById('off-g'));
    }

    public function testDeleteByClientId(): void
    {
        $this->createSession('off-h');

        $count = $this->repo->deleteByClientId(self::TEST_CLIENT_ID);
        self::assertSame(1, $count);
        self::assertNull($this->repo->findById('off-h'));
    }

    public function testStorageFailureOnFindByIdThrows(): void
    {
        $repo = new OfflineSessionRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->findById('existing-id');
    }
}
