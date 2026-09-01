<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Interfaces\RoleRepository;

/**
 * Owns the atomic admin write path for roles: the pre-delete guards
 * (user assignments, scope-role mappings) and the delete itself run in a
 * single transaction so a concurrent assignment cannot sneak in between
 * the count-check and the delete. Participates in a caller-owned transaction
 * when one is open; only opens its own otherwise.
 */
class RoleAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly RoleRepository $roles,
    ) {
    }

    public function deleteRole(string $roleId): bool
    {
        return $this->transact(function () use ($roleId): bool {
            if ($this->roles->countUsersByRoleId($roleId) > 0) {
                throw new ConflictException("role '$roleId' is still assigned to users");
            }

            if ($this->roles->countScopeRoleMappingsByRoleId($roleId) > 0) {
                throw new ConflictException("role '$roleId' is still referenced in scope-role mappings");
            }

            return $this->roles->delete($roleId);
        });
    }
}
