<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * Role claims shared across the tokens of one issuance.
 *
 * @property list<string> $realmRoles
 * @property array<string, array<string, list<string>>>|null $resourceAccess
 */
final class RoleClaims
{
    /**
     * @param list<string> $realmRoles
     * @param array<string, array<string, list<string>>>|null $resourceAccess
     */
    public function __construct(
        public readonly array $realmRoles,
        public readonly ?array $resourceAccess,
    ) {
    }
}
