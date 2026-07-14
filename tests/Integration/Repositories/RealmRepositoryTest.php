<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Repositories\RealmRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use Psr\Log\LoggerInterface;

class RealmRepositoryTest extends RepositoryTestCase
{
    private RealmRepository $repo;

    protected function setUp(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $this->repo = new RealmRepository(self::$dataSource, $logger);
    }

    public function testFindByIdReturnsRealm(): void
    {
        $realm = $this->repo->findById('84be68b8-7936-4422-bb4d-b741d2292a9f');
        self::assertNotNull($realm);
        self::assertSame('web', $realm->getName());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testFindByNameReturnsRealm(): void
    {
        $realm = $this->repo->findByName('test');
        self::assertNotNull($realm);
        self::assertSame('c03aa58c-2888-4f40-821c-4aadf5c58f6f', $realm->getId());
    }

    public function testFindByNameReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByName('ghost'));
    }
}
