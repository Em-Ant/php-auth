<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Client;
use AuthServer\Models\IssuedGrant;
use AuthServer\Models\Realm;
use AuthServer\Models\RoleClaims;
use AuthServer\Models\ScopeRoleMapping;
use AuthServer\Models\User;
use Psr\Log\LoggerInterface;

class ScopeResolver
{
    private LoggerInterface $logger;
    private RoleRepository $roles;

    public function __construct(LoggerInterface $logger, RoleRepository $roles)
    {
        $this->logger = $logger;
        $this->roles = $roles;
    }

    public function resolve(
        ?string $requested,
        Client $client,
        Realm $realm,
        bool $requireOpenid
    ): string {
        $allowed = $client->getScope() ?? $realm->getScope();
        $requestedScopes = $this->splitScope($requested);

        if ($requireOpenid && !in_array('openid', $requestedScopes, true)) {
            $this->logger->info(
                "scope 'openid' missing for client '{$client->getName()}' realm '{$realm->getName()}'"
            );
            throw OAuth2Error::invalidScope('invalid scope');
        }

        if ($requestedScopes === []) {
            return implode(' ', $allowed);
        }

        foreach ($requestedScopes as $scope) {
            if ($scope === 'openid') {
                continue;
            }
            if (!in_array($scope, $allowed, true) || !in_array($scope, $realm->getScope(), true)) {
                $this->logger->info(
                    "scope '$scope' not allowed for client '{$client->getName()}' realm '{$realm->getName()}'"
                );
                throw OAuth2Error::invalidScope('invalid scope');
            }
        }

        return implode(' ', $requestedScopes);
    }

    /**
     * Issuance-time scope/role resolution (Keycloak-style role scope
     * mappings). A client without mappings falls back to full scope — every
     * held role is emitted. A client with mappings emits only the roles
     * mapped to its granted scopes that the user actually holds, and drops
     * any mapped scope whose required role the user lacks.
     */
    public function resolveIssuance(string $grantedScope, User $user, Client $client): IssuedGrant
    {
        $mappings = $this->roles->findScopeRoleMappings($client->getId());

        if ($mappings === []) {
            return new IssuedGrant($grantedScope, $this->fullScopeClaims($user, $client));
        }

        return $this->mappedGrant($grantedScope, $user, $client, $mappings);
    }

    private function fullScopeClaims(User $user, Client $client): RoleClaims
    {
        return new RoleClaims(
            realmRoles: $this->roles->findRealmRoleNamesByUserId(
                $user->getId(),
                $user->getRealmId()
            ),
            resourceAccess: $this->resourceAccessClaim($user, $client),
        );
    }

    /**
     * @param array<string, list<ScopeRoleMapping>> $mappings
     */
    private function mappedGrant(
        string $grantedScope,
        User $user,
        Client $client,
        array $mappings
    ): IssuedGrant {
        $heldRealm = array_flip(
            $this->roles->findRealmRoleNamesByUserId($user->getId(), $user->getRealmId())
        );
        $clientRolesByClient = $this->roles->findClientRoleNamesByUserId(
            $user->getId(),
            $user->getRealmId()
        );

        $keptScopes = [];
        $realmRoles = [];
        $clientRoles = [];

        foreach ($this->splitScope($grantedScope) as $scope) {
            $scopeMappings = $mappings[$scope] ?? [];

            if ($scopeMappings !== []) {
                $included = $this->includedMappings(
                    $scopeMappings,
                    $scope,
                    $client,
                    $heldRealm,
                    $clientRolesByClient
                );

                if ($included === null) {
                    continue;
                }

                foreach ($included as $mapping) {
                    $this->collectRole($mapping, $client, $realmRoles, $clientRoles);
                }
            }

            $keptScopes[] = $scope;
        }

        return new IssuedGrant(
            implode(' ', $keptScopes),
            new RoleClaims(
                realmRoles: array_values(array_unique($realmRoles)),
                resourceAccess: $this->buildResourceAccess($client, $clientRoles),
            ),
        );
    }

    /**
     * Splits a scope's mappings into the ones whose role the user holds.
     * Returns null when a required role is missing — the whole scope must be
     * dropped from the grant.
     *
     * @param list<ScopeRoleMapping> $scopeMappings
     * @param array<string, int> $heldRealm role name => position
     * @param array<string, list<string>> $clientRolesByClient
     * @return list<ScopeRoleMapping>|null
     */
    private function includedMappings(
        array $scopeMappings,
        string $scope,
        Client $client,
        array $heldRealm,
        array $clientRolesByClient
    ): ?array {
        $included = [];

        foreach ($scopeMappings as $mapping) {
            if (!$this->holdsRole($mapping, $heldRealm, $clientRolesByClient)) {
                if ($mapping->required) {
                    $this->logger->info(
                        "scope '$scope' dropped for client '{$client->getName()}': "
                        . "required role '{$mapping->roleName}' not held by the user"
                    );
                    return null;
                }
                continue;
            }
            $included[] = $mapping;
        }

        return $included;
    }

    /**
     * @param array<string, int> $heldRealm
     * @param array<string, list<string>> $clientRolesByClient
     */
    private function holdsRole(
        ScopeRoleMapping $mapping,
        array $heldRealm,
        array $clientRolesByClient
    ): bool {
        if ($mapping->isRealmRole()) {
            return isset($heldRealm[$mapping->roleName]);
        }

        return in_array(
            $mapping->roleName,
            $clientRolesByClient[$mapping->roleClientName] ?? [],
            true
        );
    }

    /**
     * @param list<string> $realmRoles
     * @param list<string> $clientRoles
     */
    private function collectRole(
        ScopeRoleMapping $mapping,
        Client $client,
        array &$realmRoles,
        array &$clientRoles
    ): void {
        if ($mapping->isRealmRole()) {
            $realmRoles[] = $mapping->roleName;
            return;
        }

        // Only the token's own client namespace is emitted, matching the
        // full-scope behaviour of resource_access.
        if ($mapping->roleClientName === $client->getName()) {
            $clientRoles[] = $mapping->roleName;
        }
    }

    /**
     * @param list<string> $clientRoles
     * @return array<string, array<string, list<string>>>|null
     */
    private function buildResourceAccess(Client $client, array $clientRoles): ?array
    {
        if ($clientRoles === []) {
            return null;
        }
        return [$client->getName() => ['roles' => array_values(array_unique($clientRoles))]];
    }

    /**
     * `resource_access.<client>.roles` for the client the token is issued to,
     * omitted when the user holds no roles for it.
     *
     * @return array<string, array<string, list<string>>>|null
     */
    private function resourceAccessClaim(User $user, Client $client): ?array
    {
        $clientRoles = $this->roles->findClientRoleNamesByUserId(
            $user->getId(),
            $user->getRealmId()
        );
        $roles = $clientRoles[$client->getName()] ?? [];
        if ($roles === []) {
            return null;
        }
        return [$client->getName() => ['roles' => $roles]];
    }

    private function splitScope(?string $scope): array
    {
        if ($scope === null || trim($scope) === '') {
            return [];
        }

        return array_values(array_filter(explode(' ', $scope), static fn(string $s): bool => $s !== ''));
    }
}
