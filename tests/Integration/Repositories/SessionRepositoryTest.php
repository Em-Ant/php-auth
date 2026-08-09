<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\SessionStatus;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

class SessionRepositoryTest extends RepositoryTestCase
{
    private SessionRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new SessionRepository(self::$pdo);
    }

    public function testCreateAndFindById(): void
    {
        $session = $this->repo->create(
            '84be68b8-7936-4422-bb4d-b741d2292a9f',
            '586d7bb3-d386-4b57-9e99-b2a460f20b47',
            '0',
        );
        self::assertNotNull($session);
        self::assertSame(SessionStatus::Active, $session->getStatus());
        self::assertSame('0', $session->getAcr());

        $found = $this->repo->findById($session->getId());
        self::assertNotNull($found);
        self::assertSame($session->getId(), $found->getId());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testRefreshUpdatesTimestamp(): void
    {
        $session = $this->repo->create(
            '84be68b8-7936-4422-bb4d-b741d2292a9f',
            '586d7bb3-d386-4b57-9e99-b2a460f20b47',
            '0',
        );
        self::assertNull($session->getUpdatedAt());

        $result = $this->repo->refresh($session->getId());
        self::assertTrue($result);

        $refreshed = $this->repo->findById($session->getId());
        self::assertNotNull($refreshed->getUpdatedAt());
    }

    public function testSetExpiredChangesStatus(): void
    {
        $session = $this->repo->create(
            '84be68b8-7936-4422-bb4d-b741d2292a9f',
            '586d7bb3-d386-4b57-9e99-b2a460f20b47',
            '0',
        );
        self::assertSame(SessionStatus::Active, $session->getStatus());

        $result = $this->repo->setExpired($session->getId());
        self::assertTrue($result);

        $expired = $this->repo->findById($session->getId());
        self::assertSame(SessionStatus::Expired, $expired->getStatus());
    }

    public function testStorageFailureOnCreateThrows(): void
    {
        $repo = new SessionRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->create(
            '84be68b8-7936-4422-bb4d-b741d2292a9f',
            '586d7bb3-d386-4b57-9e99-b2a460f20b47',
            '0',
        );
    }
}
