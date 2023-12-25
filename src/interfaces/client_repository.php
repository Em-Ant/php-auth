<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

interface ClientRepository
{
    public function find_by_id(string $id): ?Client;
    public function find_by_name(string $id): ?Client;
}
