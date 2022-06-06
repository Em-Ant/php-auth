<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

require_once 'src/models/client.php';

interface ClientRepository
{
  public function findById(string $id): ?Client;
  public function findByClientId(string $id): ?Client;
}
