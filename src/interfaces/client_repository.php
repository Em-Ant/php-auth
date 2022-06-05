<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

require_once 'src/models/client.php';

interface ClientRepository
{
    public function findClientById(string $id): ?Client;
    public function findClientByClientId(string $id): ?Client;
}
