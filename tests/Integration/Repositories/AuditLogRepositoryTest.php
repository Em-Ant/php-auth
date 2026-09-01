<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Models\AuditAction;
use AuthServer\Models\AuditLogEntry;
use AuthServer\Repositories\AuditLogRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;

use function AuthServer\getGuid;
use function AuthServer\sqlNow;

class AuditLogRepositoryTest extends RepositoryTestCase
{
    private AuditLogRepository $repo;

    protected function setUp(): void
    {
        self::$pdo->exec('DELETE FROM audit_logs');
        $this->repo = new AuditLogRepository(self::$pdo);
    }

    public function testCreateAndFindById(): void
    {
        $entry = $this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
        );

        $created = $this->repo->create($entry);

        self::assertSame($entry->getId(), $created->getId());
        self::assertSame(AuditAction::RealmCreate, $created->getAction());

        $fetched = $this->repo->findById($entry->getId());
        self::assertNotNull($fetched);
        self::assertSame($entry->getId(), $fetched->getId());
        self::assertSame('api_key', $fetched->getActorType());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testSearchAllReturnsAllEntries(): void
    {
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f'));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmUpdate, realmId: 'c03aa58c-2888-4f40-821c-4aadf5c58f6f'));

        $result = $this->repo->searchAll(null, null, null, null, null, null, 50, 0);

        self::assertCount(2, $result['items']);
        self::assertSame(2, $result['total']);
    }

    public function testSearchAllFiltersByAction(): void
    {
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f'));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmUpdate, realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f'));
        $this->repo->create($this->makeEntry(action: AuditAction::UserCreate, realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f'));

        $result = $this->repo->searchAll('realm.create', null, null, null, null, null, 50, 0);

        self::assertCount(1, $result['items']);
        self::assertSame('realm.create', $result['items'][0]->getAction()->value);
        self::assertSame(1, $result['total']);
    }

    public function testSearchAllFiltersByRealmId(): void
    {
        $realmA = '84be68b8-7936-4422-bb4d-b741d2292a9f';
        $realmB = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';

        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmA));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmB));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmUpdate, realmId: $realmA));

        $result = $this->repo->searchAll(null, null, null, $realmA, null, null, 50, 0);

        self::assertCount(2, $result['items']);
        self::assertSame(2, $result['total']);
    }

    public function testSearchAllFiltersByDateRange(): void
    {
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-01-01 10:00:00',
        ));
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-06-15 10:00:00',
        ));
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-12-31 10:00:00',
        ));

        $result = $this->repo->searchAll(null, null, null, null, '2025-03-01', '2025-09-01', 50, 0);

        self::assertCount(1, $result['items']);
        self::assertSame('2025-06-15 10:00:00', $result['items'][0]->getCreatedAt());
    }

    public function testSearchAllPaginates(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->repo->create($this->makeEntry(
                action: AuditAction::RealmCreate,
                realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
                createdAt: "2025-01-0{$i} 10:00:00",
            ));
        }

        $page1 = $this->repo->searchAll(null, null, null, null, null, null, 2, 0);
        $page2 = $this->repo->searchAll(null, null, null, null, null, null, 2, 2);

        self::assertCount(2, $page1['items']);
        self::assertSame(5, $page1['total']);

        self::assertCount(2, $page2['items']);
        self::assertSame(5, $page2['total']);

        self::assertNotSame($page1['items'][0]->getId(), $page2['items'][0]->getId());
    }

    public function testPurgeByRealmId(): void
    {
        $realmA = '84be68b8-7936-4422-bb4d-b741d2292a9f';
        $realmB = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';

        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmA));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmA));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmB));

        $deleted = $this->repo->purge($realmA, null);

        self::assertSame(2, $deleted);

        $remaining = $this->repo->searchAll(null, null, null, null, null, null, 50, 0);
        self::assertCount(1, $remaining['items']);
        self::assertSame($realmB, $remaining['items'][0]->getRealmId());
    }

    public function testPurgeByOlderThan(): void
    {
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-01-01 10:00:00',
        ));
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-06-15 10:00:00',
        ));
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-12-31 10:00:00',
        ));

        $deleted = $this->repo->purge(null, '2025-06-01');

        self::assertSame(1, $deleted);

        $remaining = $this->repo->searchAll(null, null, null, null, null, null, 50, 0);
        self::assertCount(2, $remaining['items']);
    }

    public function testPurgeByBothFilters(): void
    {
        $realmA = '84be68b8-7936-4422-bb4d-b741d2292a9f';
        $realmB = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';

        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmA, createdAt: '2025-01-01 10:00:00'));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmA, createdAt: '2025-12-31 10:00:00'));
        $this->repo->create($this->makeEntry(action: AuditAction::RealmCreate, realmId: $realmB, createdAt: '2025-01-01 10:00:00'));

        $deleted = $this->repo->purge($realmA, '2025-06-01');

        self::assertSame(1, $deleted);

        $remaining = $this->repo->searchAll(null, null, null, null, null, null, 50, 0);
        self::assertCount(2, $remaining['items']);
    }

    public function testPurgeReturnsZeroWhenNothingMatches(): void
    {
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-06-15 10:00:00',
        ));

        $deleted = $this->repo->purge('nonexistent', null);

        self::assertSame(0, $deleted);
    }

    public function testPurgeSameDayEntriesSurvive(): void
    {
        $this->repo->create($this->makeEntry(
            action: AuditAction::RealmCreate,
            realmId: '84be68b8-7936-4422-bb4d-b741d2292a9f',
            createdAt: '2025-06-15 23:59:59',
        ));

        $deleted = $this->repo->purge(null, '2025-06-15');

        self::assertSame(0, $deleted);
    }

    private function makeEntry(
        AuditAction $action = AuditAction::RealmCreate,
        ?string $realmId = null,
        ?string $createdAt = null,
    ): AuditLogEntry {
        return new AuditLogEntry(
            id: getGuid(),
            action: $action,
            actorType: 'api_key',
            actorId: null,
            realmId: $realmId,
            targetType: 'realm',
            targetId: null,
            detail: null,
            createdAt: $createdAt ?? sqlNow(),
        );
    }
}
