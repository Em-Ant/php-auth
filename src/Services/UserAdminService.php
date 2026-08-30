<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\RoleRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\User;

/**
 * Owns the atomic admin write path for users: the user row, its realm-role
 * assignments and — for password rotations — the session revocation are
 * persisted in a single transaction, so a failure in any half leaves no
 * partial state behind.
 */
class UserAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly UserRepository $users,
        private readonly RoleRepository $roles,
        private readonly SessionRevocationService $revocations,
    ) {
    }

    /**
     * @param list<string> $realmRoles
     */
    public function createUser(User $user, array $realmRoles): User
    {
        return $this->transact(function () use ($user, $realmRoles): User {
            $created = $this->users->create($user);
            $this->roles->syncRealmRoles($created->getId(), $created->getRealmId(), $realmRoles);
            return $created;
        });
    }

    /**
     * @param list<string> $realmRoles
     */
    public function updateUser(User $user, array $realmRoles): void
    {
        $this->transact(function () use ($user, $realmRoles): void {
            $this->updateAndSync($user, $realmRoles);
        });
    }

    /**
     * Password rotation: persists the update and revokes the user's sessions
     * (and their offline refresh grants) in the same transaction, so the
     * rotation either fully applies — new hash, no live sessions — or not at
     * all, making a failed attempt safe to retry.
     *
     * @param list<string> $realmRoles
     */
    public function rotatePassword(User $user, array $realmRoles): void
    {
        $this->transact(function () use ($user, $realmRoles): void {
            $this->updateAndSync($user, $realmRoles);
            $this->revocations->revokeFor($user->getId(), null);
        });
    }

    private function updateAndSync(User $user, array $realmRoles): void
    {
        $this->users->update($user);
        $this->roles->syncRealmRoles($user->getId(), $user->getRealmId(), $realmRoles);
    }
}
