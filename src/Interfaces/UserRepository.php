<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\User;

interface UserRepository
{
    public function findById(string $id): ?User;
    public function findByEmailAndRealmId(string $email, string $realm_id): ?User;

    /** @return User[] */
    public function findAll(?string $realmId = null): array;

    public function create(User $user): User;

    public function update(User $user): bool;

    public function delete(string $id): bool;

    public function countByRealmId(string $realmId): int;

    public function countActiveByRealmId(string $realmId): int;
}
