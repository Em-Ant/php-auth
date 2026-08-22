<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Role;

interface RoleRepository
{
    public function findById(string $id): ?Role;

    /** @return Role[] */
    public function findAll(?string $realmId = null, ?string $clientId = null): array;

    public function create(Role $role): Role;

    public function delete(string $id): bool;

    /** @return string[] */
    public function findRealmRoleNamesByUserId(string $userId, string $realmId): array;

    /**
     * @return array<string, string[]>  client name → role names
     */
    public function findClientRoleNamesByUserId(string $userId, string $realmId): array;

    /** @return Role[] */
    public function findByUserId(string $userId): array;

    /**
     * Replace the realm-role assignments for a user. Client-role assignments
     * are left untouched. Participates in a caller-owned transaction when one
     * is open; only opens its own otherwise.
     *
     * @param list<string> $roleNames
     */
    public function syncRealmRoles(string $userId, string $realmId, array $roleNames): void;
}
