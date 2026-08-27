<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\User;
use AuthServer\Repositories\UserRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

use function AuthServer\getGuid;

class UserRepositoryTest extends RepositoryTestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';

    private UserRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new UserRepository(self::$pdo);
    }

    public function testFindByIdReturnsUser(): void
    {
        $user = $this->repo->findById('586d7bb3-d386-4b57-9e99-b2a460f20b47');
        self::assertNotNull($user);
        self::assertSame('emant', $user->getName());
        self::assertSame('test@example.com', $user->getEmail());
    }

    public function testCreatePersistsEmailVerifiedIntegerConvention(): void
    {
        $user = $this->repo->create($this->user('unverified@example.com', true, '', false));

        $stored = self::$pdo->prepare('SELECT email_verified FROM users WHERE id = :id');
        $stored->execute([':id' => $user->getId()]);

        self::assertSame(0, (int) $stored->fetchColumn());

        $loaded = $this->repo->findById($user->getId());
        self::assertNotNull($loaded);
        self::assertFalse($loaded->getEmailVerified());
    }

    public function testSeedUsersAreEmailVerified(): void
    {
        // Hand-created seed users become verified (see db/seed.sql UPDATE).
        foreach (['586d7bb3-d386-4b57-9e99-b2a460f20b47', 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a'] as $id) {
            $user = $this->repo->findById($id);
            self::assertNotNull($user);
            self::assertTrue($user->getEmailVerified());
        }
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

    public function testStorageFailureThrows(): void
    {
        $repo = new UserRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->findById('586d7bb3-d386-4b57-9e99-b2a460f20b47');
    }

    public function testCreatePersistsValidWithIntegerConvention(): void
    {
        $user = $this->repo->create($this->user('integer-convention@example.com', true));

        $stored = self::$pdo->prepare('SELECT valid FROM users WHERE id = :id');
        $stored->execute([':id' => $user->getId()]);

        self::assertSame(1, (int) $stored->fetchColumn());
    }

    public function testUpdatePersistsDisabledUserAsIntegerZero(): void
    {
        $user = $this->repo->create($this->user('disable-me@example.com', true));

        $this->repo->update($this->user($user->getEmail(), false, $user->getId()));

        $loaded = $this->repo->findById($user->getId());
        self::assertNotNull($loaded);
        self::assertFalse($loaded->getValid());

        $stored = self::$pdo->prepare('SELECT valid FROM users WHERE id = :id');
        $stored->execute([':id' => $user->getId()]);

        self::assertSame(0, (int) $stored->fetchColumn());
    }

    public function testFindByIdReadsLegacyStringConvention(): void
    {
        // Rows written before migration 007 hold 'TRUE'/'FALSE' strings;
        // they must keep loading correctly alongside the integer convention.
        $trueId = getGuid();
        $falseId = getGuid();

        $this->insertRawUser($trueId, 'legacy-true@example.com', 'TRUE');
        $this->insertRawUser($falseId, 'legacy-false@example.com', 'FALSE');

        $enabled = $this->repo->findById($trueId);
        $disabled = $this->repo->findById($falseId);

        self::assertNotNull($enabled);
        self::assertTrue($enabled->getValid());
        self::assertNotNull($disabled);
        self::assertFalse($disabled->getValid());
    }

    private function user(string $email, bool $valid, string $id = '', bool $emailVerified = true): User
    {
        return new User(
            $id,
            self::TEST_REALM,
            'Bool Test',
            $email,
            password_hash('pass', PASSWORD_BCRYPT, ['cost' => 4]),
            '2025-01-01 00:00:00',
            $valid,
            $emailVerified,
        );
    }

    private function insertRawUser(string $id, string $email, string $valid): void
    {
        // Binding valid as a string reproduces the pre-007 TEXT storage exactly.
        $statement = self::$pdo->prepare(
            "INSERT INTO users (id, realm_id, name, email, password, valid)
             VALUES (:id, :realm_id, 'Legacy', :email, 'hash', :valid)"
        );
        $statement->execute([':id' => $id, ':realm_id' => self::TEST_REALM, ':email' => $email, ':valid' => $valid]);
    }
}
