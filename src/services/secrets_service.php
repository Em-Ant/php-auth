<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Lib\Utils;

require_once 'src/lib/utils.php';
class SecretsService
{
  static function generate_code(): string
  {
    return join('.', [Utils::get_guid(), Utils::get_guid(), Utils::get_guid()]);
  }

  static function hash_password(string $password): string
  {
    return
      password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
  }

  static function validate_password(string $plain, string $hash): bool
  {
    return password_verify($plain, $hash);
  }
}
