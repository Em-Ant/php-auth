<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

interface ClientRepository
{
    public function findById(string $id): ?Client;
    public function findByName(string $id): ?Client;

    /** @return Client[] */
    public function findAll(?string $realmId = null): array;

    public function create(Client $client): Client;

    public function update(Client $client): bool;

    public function delete(string $id): bool;

    public function countByRealmId(string $realmId): int;
}
