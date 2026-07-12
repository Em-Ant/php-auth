<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Session;

interface SessionRepository
{
    public function findById(string $id): ?Session;

    public function create(
        string $realm_id,
        string $user_id,
        string $acr
    ): ?Session;

    public function refresh(
        string $id
    ): bool;

    public function setExpired(
        string $id
    ): bool;
}
