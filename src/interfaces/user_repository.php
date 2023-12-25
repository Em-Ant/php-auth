<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\User;

interface UserRepository
{
    public function findById(string $id): ?User;
    public function findByEmail(string $email): ?User;
}
