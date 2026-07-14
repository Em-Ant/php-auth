<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Repositories\UserRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use Psr\Log\LoggerInterface;

class UserRepositoryTest extends RepositoryTestCase
{
    private UserRepository $repo;

    protected function setUp(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $this->repo = new UserRepository(self::$dataSource, $logger);
    }

    public function testFindByIdReturnsUser(): void
    {
        $user = $this->repo->findById('586d7bb3-d386-4b57-9e99-b2a460f20b47');
        self::assertNotNull($user);
        self::assertSame('emant', $user->getName());
        self::assertSame('test@example.com', $user->getEmail());
        self::assertSame(['basic', 'admin'], $user->getRealmRoles());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testFindByEmailAndRealmIdReturnsUser(): void
    {
        $user = $this->repo->findByEmailAndRealmId(
            'test@example.com',
            '84be68b8-7936-4422-bb4d-b741d2292a9f'
        );
        self::assertNotNull($user);
        self::assertSame('emant', $user->getName());
    }

    public function testFindByEmailAndRealmIdWrongRealmReturnsNull(): void
    {
        $user = $this->repo->findByEmailAndRealmId(
            'test@example.com',
            'nonexistent'
        );
        self::assertNull($user);
    }

    public function testFindByEmailAndRealmIdWrongEmailReturnsNull(): void
    {
        $user = $this->repo->findByEmailAndRealmId(
            'wrong@example.com',
            '84be68b8-7936-4422-bb4d-b741d2292a9f'
        );
        self::assertNull($user);
    }
}
