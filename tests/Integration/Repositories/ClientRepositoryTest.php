<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

class ClientRepositoryTest extends RepositoryTestCase
{
    private ClientRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new ClientRepository(self::$pdo);
    }

    public function testFindByIdReturnsClient(): void
    {
        $client = $this->repo->findById('a540c566-dfbf-430a-9941-fb8531c022d4');
        self::assertNotNull($client);
        self::assertSame('local', $client->getName());
        self::assertSame('http://localhost:5173', $client->getUri());
        self::assertFalse($client->requiresAuth());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testFindByNameReturnsClient(): void
    {
        $client = $this->repo->findByName('playground');
        self::assertNotNull($client);
        self::assertSame('f83a1166-c39a-4e01-884e-bfe5073a4473', $client->getId());
    }

    public function testFindByNameReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByName('ghost'));
    }

    public function testStorageFailureThrows(): void
    {
        $repo = new ClientRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->findById('a540c566-dfbf-430a-9941-fb8531c022d4');
    }
}
