<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\AuditAction;
use AuthServer\Models\Role;
use Psr\Http\Message\ServerRequestInterface;

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
        private readonly AuditLogWriter $auditLog,
    ) {
    }

    /**
     * @param array{
     *     name: string,
     *     description?: string|null,
     * } $params
     */
    public function create(string $realmId, ?string $clientId, array $params, ServerRequestInterface $request): Role
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

        $created = $this->roles->create($role);

        $this->auditLog->log($request, AuditAction::RoleCreate, 'role', $created->getId(), $realmId);

        return $created;
    }

    /**
     * @param array{
     *     name: string,
     *     description?: string|null,
     * } $params
     */
    public function update(Role $existing, array $params, ServerRequestInterface $request): Role
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

        $this->auditLog->log($request, AuditAction::RoleUpdate, 'role', $role->getId(), $role->getRealmId());

        return $role;
    }

    public function deleteRole(string $roleId, ServerRequestInterface $request): bool
    {
        $existing = $this->roles->findById($roleId);
        $realmId = $existing?->getRealmId();

        $result = $this->transact(function () use ($roleId): bool {
            if ($this->roles->countUsersByRoleId($roleId) > 0) {
                throw new ConflictException("role '$roleId' is still assigned to users");
            }

            if ($this->roles->countScopeRoleMappingsByRoleId($roleId) > 0) {
                throw new ConflictException("role '$roleId' is still referenced in scope-role mappings");
            }

            return $this->roles->delete($roleId);
        });

        if ($existing !== null) {
            $this->auditLog->log($request, AuditAction::RoleDelete, 'role', $roleId, $realmId);
        }

        return $result;
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
