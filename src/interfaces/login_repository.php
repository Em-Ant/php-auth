<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Login;

interface LoginRepository
{
    public function findById(string $id): ?Login;
    public function findByCode(string $code): ?Login;
    public function findByrefreshToken(string $token): ?Login;

    public function createPending(
        string $client_id,
        string $state,
        string $nonce,
        string $scope,
        string $redirect_uri,
        string $response_mode,
        ?string $code_challenge
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
}
