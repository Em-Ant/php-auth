<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

interface ClientRepository
{
    public function findById(string $id): ?Client;
    public function findByName(string $id): ?Client;
}
