<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Repositories\TokenBlacklistRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

class TokenBlacklistRepositoryTest extends RepositoryTestCase
{
    private TokenBlacklistRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new TokenBlacklistRepository(self::$pdo);
    }

    public function testAddThenExists(): void
    {
        self::assertFalse($this->repo->exists('jti-1'));

        $added = $this->repo->add('jti-1', time() + 3600);
        self::assertTrue($added);

        self::assertTrue($this->repo->exists('jti-1'));
    }

    public function testExistsReturnsFalseForMissing(): void
    {
        self::assertFalse($this->repo->exists('never-added'));
    }

    public function testStorageFailureOnExistsThrows(): void
    {
        $repo = new TokenBlacklistRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->exists('jti-1');
    }

    public function testStorageFailureOnAddThrows(): void
    {
        $repo = new TokenBlacklistRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->add('jti-1', time() + 3600);
    }
}
