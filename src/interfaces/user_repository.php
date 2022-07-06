<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\User;

require_once 'src/models/user.php';

interface UserRepository
{
  public function findById(string $id): ?User;
  public function findByEmail(string $email): ?User;
}
