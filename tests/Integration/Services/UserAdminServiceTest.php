<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Models\User;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\OfflineSessionRepository as RepoOfflineSessionRepository;
use AuthServer\Repositories\SessionRepository as RepoSessionRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\SecretsService;
use AuthServer\Services\SessionRevocationService;
use AuthServer\Services\UserAdminService;
use AuthServer\Tests\Integration\RepositoryTestCase;

class UserAdminServiceTest extends RepositoryTestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const WEB_REALM = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const EMANT_TEST = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';
    private const EMANT_EMAIL = 'test@example.com';
    private const LOCAL_CLIENT = 'a540c566-dfbf-430a-9941-fb8531c022d4';
    private const TEST_PASSWORD = 'tst';

    public function testCreateUserPersistsUserWithoutRoles(): void
    {
        $service = $this->service();

        $created = $service->createUser($this->createParams('u-atomic-create', 'atomic-create@example.test'));

        $stored = $this->users()->findById($created->getId());
        self::assertNotNull($stored);
        self::assertSame('atomic-create@example.test', $stored->getEmail());
    }

    public function testCreateUserRejectsDuplicateEmail(): void
    {
        $service = $this->service();

        $this->expectException(ConflictException::class);
        $service->createUser($this->createParams('u-dup-1', self::EMANT_EMAIL));
    }

    public function testCreateUserRejectsUnknownRealm(): void
    {
        $service = $this->service();

        $this->expectException(ValidationFailed::class);
        $service->createUser([
            'realm_id' => 'no-such-realm',
            'email' => 'ghost@example.test',
            'password' => self::TEST_PASSWORD,
        ]);
    }

    public function testUpdateUserRejectsRealmChange(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-move-realm', 'move-realm@example.test'));

        $this->expectException(ValidationFailed::class);
        $service->updateUser($user, ['realm_id' => self::WEB_REALM]);
    }

    public function testUpdateUserAcceptsSameRealmId(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-same-realm', 'same-realm@example.test'));

        $updated = $service->updateUser($user, ['realm_id' => self::TEST_REALM, 'name' => 'same realm ok']);

        self::assertSame('same realm ok', $updated->getName());
        self::assertSame(self::TEST_REALM, $updated->getRealmId());
    }

    public function testUpdateUserPersistsChanges(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-atomic-update', 'atomic-update@example.test'));

        $service->updateUser($user, [
            'name' => 'renamed',
            'valid' => false,
        ]);

        $stored = $this->users()->findById($user->getId());
        self::assertNotNull($stored);
        self::assertSame('renamed', $stored->getName());
        self::assertFalse($stored->getValid());
    }

    public function testUpdateUserWithPasswordRotatesAndRevokesSessions(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-rotate-ok', 'rotate-ok@example.test'));
        $this->insertSession($user->getId());

        $service->updateUser($user, ['password' => self::TEST_PASSWORD]);

        $stored = $this->users()->findById($user->getId());
        self::assertNotNull($stored);
        self::assertTrue($this->secrets()->validatePassword(self::TEST_PASSWORD, $stored->getPassword()));
        self::assertSame(0, $this->countSessions($user->getId()));
    }

    public function testUpdateUserRejectsEmptyPassword(): void
    {
        $service = $this->service();
        $user = $this->users()->findById(self::EMANT_TEST);
        self::assertNotNull($user);

        $this->expectException(ValidationFailed::class);
        $service->updateUser($user, ['password' => '']);
    }

    public function testUpdateUserWithPasswordRollsBackEverythingWhenRevocationFails(): void
    {
        $service = $this->serviceWith($this->failingRevocations());
        $user = $service->createUser($this->createParams('u-rotate-fail', 'rotate-fail@example.test'));
        $this->insertSession($user->getId());

        try {
            $service->updateUser($user, ['password' => self::TEST_PASSWORD . '-doomed']);
            self::fail('expected StorageFailed');
        } catch (\AuthServer\Exceptions\StorageFailed) {
            // Rotation is all-or-nothing: neither the new hash nor the
            // revocation may survive a failure.
            $after = $this->users()->findById($user->getId());
            self::assertNotNull($after);
            self::assertSame(1, $this->countSessions($user->getId()));
        }
    }

    public function testDeleteUserRemovesUserAndExpiredOfflineGrants(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-delete-ok', 'delete-ok@example.test'));

        $service->deleteUser($user->getId());

        self::assertNull($this->users()->findById($user->getId()));
    }

    public function testDeleteUserBlockedByActiveSessions(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-delete-sess', 'delete-sess@example.test'));
        $this->insertSession($user->getId());

        $this->expectException(ConflictException::class);
        $service->deleteUser($user->getId());
    }

    public function testDeleteUserBlockedByActiveOfflineSession(): void
    {
        $service = $this->service();
        $user = $service->createUser($this->createParams('u-delete-offline', 'delete-offline@example.test'));
        $this->insertOfflineSession($user->getId());

        $this->expectException(ConflictException::class);
        $service->deleteUser($user->getId());
    }

    /**
     * @return array{
     *     realm_id: string,
     *     email: string,
     *     password: string,
     *     name: string,
     * }
     */
    private function createParams(string $id, string $email): array
    {
        return [
            'realm_id' => self::TEST_REALM,
            'email' => $email,
            'password' => self::TEST_PASSWORD,
            'name' => 'Atomic Test ' . $id,
        ];
    }

    private function service(): UserAdminService
    {
        return $this->serviceWith($this->revocations());
    }

    private function serviceWith(SessionRevocationService $revocations): UserAdminService
    {
        return new UserAdminService(
            self::$pdo,
            $this->users(),
            $revocations,
            $this->secrets(),
            $this->realms(),
            $this->sessions(),
            $this->offlineSessions(),
        );
    }

    private function users(): UserRepository
    {
        return new UserRepository(self::$pdo);
    }

    private function secrets(): SecretsService
    {
        return new SecretsService(['algorithm' => 'bcrypt', 'bcrypt_cost' => 4]);
    }

    private function realms(): RealmRepository
    {
        return new \AuthServer\Repositories\RealmRepository(self::$pdo);
    }

    private function sessions(): SessionRepository
    {
        return new RepoSessionRepository(self::$pdo);
    }

    private function offlineSessions(): OfflineSessionRepository
    {
        return new RepoOfflineSessionRepository(self::$pdo);
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
            new RepoSessionRepository(self::$pdo),
            new LoginRepository(self::$pdo),
            new RepoOfflineSessionRepository(self::$pdo),
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
                throw new \AuthServer\Exceptions\StorageFailed('simulated revocation failure');
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

    private function insertOfflineSession(string $userId): void
    {
        $stmt = self::$pdo->prepare(
            "INSERT INTO offline_sessions (id, realm_id, user_id, client_id, acr, scope, refresh_token, status)
             VALUES (:id, :realm, :user, :client, '0', 'openid', 'token', 'ACTIVE')"
        );
        $stmt->execute([
            ':id' => 'offline-' . $userId,
            ':realm' => self::TEST_REALM,
            ':user' => $userId,
            ':client' => self::LOCAL_CLIENT,
        ]);
    }

    private function countSessions(string $userId): int
    {
        $stmt = self::$pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :user');
        $stmt->execute([':user' => $userId]);
        return (int) $stmt->fetchColumn();
    }
}
