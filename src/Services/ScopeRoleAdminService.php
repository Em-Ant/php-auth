<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\AuditAction;
use AuthServer\Models\Client;
use AuthServer\Models\ScopeRoleMapping;
use Psr\Http\Message\ServerRequestInterface;

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
        private readonly AuditLogWriter $auditLog,
    ) {
    }

    public function create(
        string $clientId,
        string $scope,
        string $roleId,
        bool $required,
        ServerRequestInterface $request,
    ): ScopeRoleMapping {
        $client = $this->assertScopeIsValidForClient($clientId, $scope);

        $role = $this->roles->findById($roleId);
        if ($role === null) {
            throw new ValidationFailed("unknown role '$roleId'");
        }

        if ($this->roles->findScopeRoleMapping($clientId, $scope, $roleId) !== null) {
            throw new ConflictException("mapping for scope '$scope' and role '$roleId' already exists");
        }

        $this->roles->createScopeRoleMapping($clientId, $scope, $roleId, $required);

        $this->logScopeRoleAudit(
            $request,
            AuditAction::ScopeRoleCreate,
            $clientId,
            $scope,
            $roleId,
            $client->getRealmId(),
        );

        return new ScopeRoleMapping($roleId, $scope, $role->getName(), null, $required);
    }

    public function update(
        string $clientId,
        string $scope,
        string $roleId,
        bool $required,
        ServerRequestInterface $request,
    ): void {
        $client = $this->assertScopeIsValidForClient($clientId, $scope);
        $this->roles->updateScopeRoleMapping($clientId, $scope, $roleId, $required);

        $this->logScopeRoleAudit(
            $request,
            AuditAction::ScopeRoleUpdate,
            $clientId,
            $scope,
            $roleId,
            $client->getRealmId(),
        );
    }

    public function delete(string $clientId, string $scope, string $roleId, ServerRequestInterface $request): void
    {
        $client = $this->clients->findById($clientId);
        $realmId = $client?->getRealmId();

        // Delete is idempotent by contract (204 even for a missing mapping), so
        // record the event only when a mapping actually existed — an audit log
        // must never claim a delete that did not happen.
        if ($this->roles->deleteScopeRoleMapping($clientId, $scope, $roleId)) {
            $this->logScopeRoleAudit($request, AuditAction::ScopeRoleDelete, $clientId, $scope, $roleId, $realmId);
        }
    }

    private function logScopeRoleAudit(
        ServerRequestInterface $request,
        AuditAction $action,
        string $clientId,
        string $scope,
        string $roleId,
        ?string $realmId,
    ): void {
        $this->auditLog->log(
            $request,
            $action,
            'scope_role',
            $roleId,
            $realmId,
            ['client_id' => $clientId, 'scope' => $scope],
        );
    }

    private function assertScopeIsValidForClient(string $clientId, string $scope): Client
    {
        $client = $this->clients->findById($clientId);
        $realm = $this->realms->findById($client->getRealmId());

        if (!in_array($scope, $realm->getScope(), true)) {
            throw new ValidationFailed("scope '$scope' is not allowed in this realm");
        }

        return $client;
    }
}
