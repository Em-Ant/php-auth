<?php

declare(strict_types=1);

namespace AuthServer\Services;

class SecretsService
{
  static function generate_code(): string
  {
    return str_replace(['+', '/', '='], '', base64_encode(random_bytes(64)));
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
