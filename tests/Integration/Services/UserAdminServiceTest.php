<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Services;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\User;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\OfflineSessionRepository;
use AuthServer\Repositories\RoleRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\SessionRevocationService;
use AuthServer\Services\UserAdminService;
use AuthServer\Tests\Integration\RepositoryTestCase;

class UserAdminServiceTest extends RepositoryTestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const EMANT_TEST = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';

    public function testCreateUserPersistsUserAndRealmRoles(): void
    {
        $service = $this->service();
        $user = self::user('u-atomic-create', 'atomic-create@example.test');

        $created = $service->createUser($user, ['basic']);

        $stored = $this->users()->findById($created->getId());
        self::assertNotNull($stored);
        self::assertSame('atomic-create@example.test', $stored->getEmail());
        self::assertSame(['basic'], $this->roles()->findRealmRoleNamesByUserId($stored->getId(), self::TEST_REALM));
    }

    public function testCreateUserRollsBackUserRowWhenRoleSyncFails(): void
    {
        $service = new UserAdminService(self::$pdo, $this->users(), $this->failingRoles(), $this->revocations());
        $user = self::user('u-atomic-fail', 'atomic-fail@example.test');

        try {
            $service->createUser($user, ['basic']);
            self::fail('expected StorageFailed');
        } catch (StorageFailed) {
            self::assertNull($this->users()->findById('u-atomic-fail'));
        }
    }

    public function testUpdateUserRollsBackWhenRoleSyncFails(): void
    {
        $service = new UserAdminService(self::$pdo, $this->users(), $this->failingRoles(), $this->revocations());
        $existing = $this->users()->findById(self::EMANT_TEST);
        self::assertNotNull($existing);

        $renamed = new User(
            $existing->getId(),
            $existing->getRealmId(),
            'renamed-but-doomed',
            $existing->getEmail(),
            $existing->getPassword(),
            $existing->getCreatedAt()->format('Y-m-d H:i:s'),
            $existing->getValid()
        );

        try {
            $service->updateUser($renamed, ['basic']);
            self::fail('expected StorageFailed');
        } catch (StorageFailed) {
            $after = $this->users()->findById(self::EMANT_TEST);
            self::assertNotNull($after);
            self::assertNotSame('renamed-but-doomed', $after->getName());
        }
    }

    public function testUpdateUserPersistsChangesAndRolesTogether(): void
    {
        $service = $this->service();
        $user = self::user('u-atomic-update', 'atomic-update@example.test');
        $service->createUser($user, ['basic']);

        $changed = new User(
            $user->getId(),
            $user->getRealmId(),
            'renamed',
            $user->getEmail(),
            $user->getPassword(),
            $user->getCreatedAt()->format('Y-m-d H:i:s'),
            false
        );
        $service->updateUser($changed, ['manager']);

        $stored = $this->users()->findById($user->getId());
        self::assertNotNull($stored);
        self::assertSame('renamed', $stored->getName());
        self::assertFalse($stored->getValid());
        self::assertSame(['manager'], $this->roles()->findRealmRoleNamesByUserId($user->getId(), self::TEST_REALM));
    }

    public function testRotatePasswordPersistsHashAndRevokesSessions(): void
    {
        $service = $this->service();
        $user = self::user('u-rotate-ok', 'rotate-ok@example.test');
        $service->createUser($user, ['basic']);
        $this->insertSession($user->getId());

        $service->rotatePassword(self::withPassword($user, 'new-hash'), ['basic']);

        $stored = $this->users()->findById($user->getId());
        self::assertNotNull($stored);
        self::assertSame('new-hash', $stored->getPassword());
        self::assertSame(0, $this->countSessions($user->getId()));
    }

    public function testRotatePasswordRollsBackEverythingWhenRevocationFails(): void
    {
        $service = new UserAdminService(self::$pdo, $this->users(), $this->roles(), $this->failingRevocations());
        $user = self::user('u-rotate-fail', 'rotate-fail@example.test');
        $service->createUser($user, ['basic']);
        $this->insertSession($user->getId());

        try {
            $service->rotatePassword(self::withPassword($user, 'doomed-hash'), ['basic']);
            self::fail('expected StorageFailed');
        } catch (StorageFailed) {
            // Rotation is all-or-nothing: neither the new hash nor the
            // revocation may survive a failure.
            $after = $this->users()->findById($user->getId());
            self::assertNotNull($after);
            self::assertSame('hash', $after->getPassword());
            self::assertSame(1, $this->countSessions($user->getId()));
        }
    }

    private function service(): UserAdminService
    {
        return new UserAdminService(self::$pdo, $this->users(), $this->roles(), $this->revocations());
    }

    private function users(): UserRepository
    {
        return new UserRepository(self::$pdo);
    }

    private function roles(): RoleRepository
    {
        return new RoleRepository(self::$pdo);
    }

    private function revocations(): SessionRevocationService
    {
        return new SessionRevocationService(self::$pdo, ...$this->revocationDeps());
    }

    /**
     * @return array{SessionRepository, LoginRepository, OfflineSessionRepository}
     */
    private function revocationDeps(): array
    {
        return [
            new SessionRepository(self::$pdo),
            new LoginRepository(self::$pdo),
            new OfflineSessionRepository(self::$pdo),
        ];
    }

    /**
     * A revocation service whose bulk path always fails, simulating a storage
     * error after the user-row write inside the rotation transaction.
     */
    private function failingRevocations(): SessionRevocationService
    {
        return new class (self::$pdo, ...$this->revocationDeps()) extends SessionRevocationService {
            #[\Override]
            public function revokeFor(?string $userId, ?string $clientId): int
            {
                throw new StorageFailed('simulated revocation failure');
            }
        };
    }

    private function insertSession(string $userId): void
    {
        $stmt = self::$pdo->prepare(
            "INSERT INTO sessions (id, realm_id, user_id, acr, status)
             VALUES (:id, :realm, :user, '0', 'ACTIVE')"
        );
        $stmt->execute([':id' => 'sess-' . $userId, ':realm' => self::TEST_REALM, ':user' => $userId]);
    }

    private function countSessions(string $userId): int
    {
        $stmt = self::$pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :user');
        $stmt->execute([':user' => $userId]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * A role repository whose write path always fails, simulating a storage
     * error between the user-row write and the role sync.
     */
    private function failingRoles(): RoleRepository
    {
        return new class (self::$pdo) extends RoleRepository {
            #[\Override]
            public function syncRealmRoles(string $userId, string $realmId, array $roleNames): void
            {
                throw new StorageFailed('simulated role sync failure');
            }
        };
    }

    private static function user(string $id, string $email): User
    {
        return new User($id, self::TEST_REALM, 'Atomic Test', $email, 'hash', '2026-01-01 00:00:00', true);
    }

    private static function withPassword(User $user, string $password): User
    {
        return new User(
            $user->getId(),
            $user->getRealmId(),
            $user->getName(),
            $user->getEmail(),
            $password,
            $user->getCreatedAt()->format('Y-m-d H:i:s'),
            $user->getValid()
        );
    }
}
