<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Role;

use function AuthServer\getGuid;

/**
 * Owns the atomic admin write path for roles: the pre-delete guards
 * (user assignments, scope-role mappings) and the delete itself run in a
 * single transaction so a concurrent assignment cannot sneak in between
 * the count-check and the delete. Create/update validate realm + client
 * references and in-context duplicates before persisting. Participates in
 * a caller-owned transaction when one is open; only opens its own otherwise.
 */
class RoleAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly RoleRepository $roles,
        private readonly RealmRepository $realms,
        private readonly ClientRepository $clients,
    ) {
    }

    /**
     * @param array{
     *     name: string,
     *     description?: string|null,
     * } $params
     */
    public function create(string $realmId, ?string $clientId, array $params): Role
    {
        if ($this->realms->findById($realmId) === null) {
            throw new ValidationFailed("unknown realm '$realmId'");
        }

        if ($clientId !== null && $this->clients->findById($clientId) === null) {
            throw new ValidationFailed("unknown client '$clientId'");
        }

        $name = $params['name'];
        if ($this->findDuplicate($name, $realmId, $clientId, null) !== null) {
            throw new ConflictException("role '$name' already exists in this context");
        }

        $role = new Role(
            getGuid(),
            $realmId,
            $clientId,
            $name,
            $params['description'] ?? null,
            new \DateTime('now', new \DateTimeZone('UTC')),
        );

        return $this->roles->create($role);
    }

    /**
     * @param array{
     *     name: string,
     *     description?: string|null,
     * } $params
     */
    public function update(Role $existing, array $params): Role
    {
        $name = $params['name'];
        if (
            $this->findDuplicate(
                $name,
                $existing->getRealmId(),
                $existing->getClientId(),
                $existing->getId()
            ) !== null
        ) {
            throw new ConflictException("role '$name' already exists in this context");
        }

        $role = new Role(
            $existing->getId(),
            $existing->getRealmId(),
            $existing->getClientId(),
            $name,
            $params['description'] ?? $existing->getDescription(),
            $existing->getCreatedAt(),
        );

        $this->roles->update($role);

        return $role;
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

    private function findDuplicate(string $name, string $realmId, ?string $clientId, ?string $excludeId): ?Role
    {
        $existing = $this->roles->findAll($realmId, $clientId);
        foreach ($existing as $role) {
            if ($role->getName() === $name && $role->getId() !== $excludeId) {
                return $role;
            }
        }
        return null;
    }
}
