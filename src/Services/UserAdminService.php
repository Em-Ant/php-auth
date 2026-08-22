<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\RoleRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\User;

/**
 * Owns the atomic admin write path for users: the user row and its realm-role
 * assignments are persisted in a single transaction, so a failure in either
 * half leaves no partial user behind.
 */
class UserAdminService
{
    public function __construct(
        private readonly \PDO $db,
        private readonly UserRepository $users,
        private readonly RoleRepository $roles,
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
            $this->users->update($user);
            $this->roles->syncRealmRoles($user->getId(), $user->getRealmId(), $realmRoles);
        });
    }

    private function transact(\Closure $work): mixed
    {
        $this->db->beginTransaction();

        try {
            $result = $work();
            $this->db->commit();
            return $result;
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
}
