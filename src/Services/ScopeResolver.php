<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class ScopeResolver
{
    private LoggerInterface $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
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
            throw new ValidationFailed('invalid scope');
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
                throw new ValidationFailed('invalid scope');
            }
        }

        return implode(' ', $requestedScopes);
    }

    private function splitScope(?string $scope): array
    {
        if ($scope === null || trim($scope) === '') {
            return [];
        }

        return explode(' ', $scope);
    }
}
