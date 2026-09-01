<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\ScopeRoleMapping;

/**
 * Owns the admin write path for client scope-role mappings: scope validity
 * against the client's realm, role existence, duplicate detection and the
 * mapping writes. The client-404 existence check stays in the controller
 * (it needs the request for the HTTP exception).
 */
class ScopeRoleAdminService
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly RoleRepository $roles,
        private readonly RealmRepository $realms,
    ) {
    }

    public function create(string $clientId, string $scope, string $roleId, bool $required): ScopeRoleMapping
    {
        $this->assertScopeIsValidForClient($clientId, $scope);

        $role = $this->roles->findById($roleId);
        if ($role === null) {
            throw new ValidationFailed("unknown role '$roleId'");
        }

        if ($this->roles->findScopeRoleMapping($clientId, $scope, $roleId) !== null) {
            throw new ConflictException("mapping for scope '$scope' and role '$roleId' already exists");
        }

        $this->roles->createScopeRoleMapping($clientId, $scope, $roleId, $required);

        return new ScopeRoleMapping($roleId, $scope, $role->getName(), null, $required);
    }

    public function update(string $clientId, string $scope, string $roleId, bool $required): void
    {
        $this->assertScopeIsValidForClient($clientId, $scope);
        $this->roles->updateScopeRoleMapping($clientId, $scope, $roleId, $required);
    }

    public function delete(string $clientId, string $scope, string $roleId): void
    {
        $this->roles->deleteScopeRoleMapping($clientId, $scope, $roleId);
    }

    private function assertScopeIsValidForClient(string $clientId, string $scope): void
    {
        $client = $this->clients->findById($clientId);
        $realm = $this->realms->findById($client->getRealmId());

        if (!in_array($scope, $realm->getScope(), true)) {
            throw new ValidationFailed("scope '$scope' is not allowed in this realm");
        }
    }
}
