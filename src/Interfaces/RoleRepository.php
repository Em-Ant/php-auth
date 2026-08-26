<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Role;
use AuthServer\Models\ScopeRoleMapping;

interface RoleRepository
{
    public function findById(string $id): ?Role;

    /** @return Role[] */
    public function findAll(?string $realmId = null, ?string $clientId = null): array;

    public function create(Role $role): Role;

    public function update(Role $role): bool;

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
     * Role scope mappings of a client, grouped by scope name. A client with
     * no mappings falls back to full scope (all held roles are emitted).
     *
     * @return array<string, list<ScopeRoleMapping>>
     */
    public function findScopeRoleMappings(string $clientId): array;

    /**
     * Replace the realm-role assignments for a user. Client-role assignments
     * are left untouched. Participates in a caller-owned transaction when one
     * is open; only opens its own otherwise.
     *
     * @param list<string> $roleNames
     */
    public function syncRealmRoles(string $userId, string $realmId, array $roleNames): void;

    /**
     * Filtered, paged listing. `total` covers all rows matching the filters.
     *
     * @return array{items: Role[], total: int}
     */
    public function searchAll(?string $realmId, ?string $clientId, int $limit, int $offset): array;

    public function countUsersByRoleId(string $roleId): int;

    public function assignRoleToUser(string $userId, string $roleId): void;

    public function removeRoleFromUser(string $userId, string $roleId): bool;

    public function userHasRole(string $userId, string $roleId): bool;

    public function createScopeRoleMapping(string $clientId, string $scope, string $roleId, bool $required): void;

    public function updateScopeRoleMapping(string $clientId, string $scope, string $roleId, bool $required): bool;

    public function deleteScopeRoleMapping(string $clientId, string $scope, string $roleId): bool;

    public function findScopeRoleMapping(string $clientId, string $scope, string $roleId): ?array;

    public function countScopeRoleMappingsByRoleId(string $roleId): int;
}
