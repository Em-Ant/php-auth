<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Login;

interface LoginRepository
{
    public function findById(string $id): ?Login;
    public function findByCode(string $code, string $realmId): ?Login;
    public function findByRefreshToken(string $token, string $realmId): ?Login;

    public function createPending(
        string $client_id,
        string $state,
        string $nonce,
        string $scope,
        string $redirect_uri,
        string $response_mode,
        ?string $code_challenge,
        ?string $csrf_token
    ): ?Login;

    public function createAuthenticated(
        string $client_id,
        string $session_id,
        string $state,
        string $nonce,
        string $scope,
        string $redirect_uri,
        string $response_mode,
        string $code,
        ?string $code_challenge
    ): ?Login;

    public function setAuthenticated(
        string $id,
        string $session_id,
        string $code,
    ): bool;

    public function setActive(
        string $id,
        string $token
    ): bool;

    public function refresh(
        string $id,
        string $token
    ): bool;

    public function setExpired(
        string $id
    ): bool;

    public function delete(string $id): bool;

    public function deleteBySessionId(string $sessionId): int;

    public function findAll(?string $realmId = null, ?string $clientId = null): array;

    public function countByClientId(string $clientId): int;

    public function countActiveByClientId(string $clientId): int;
}
