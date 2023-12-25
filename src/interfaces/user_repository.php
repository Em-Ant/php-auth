<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\User;

interface UserRepository
{
    public function find_by_id(string $id): ?User;
    public function find_by_email(string $email): ?User;
}
