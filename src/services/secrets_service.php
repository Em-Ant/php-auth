<?php

declare(strict_types=1);

namespace AuthServer\Services;

use Emant\BrowniePhp\Utils;

class SecretsService
{
    public static function generateCode(): string
    {
        return join('.', [Utils::get_guid(), Utils::get_guid(), Utils::get_guid()]);
    }

    public static function hashPassword(string $password): string
    {
        return
            password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
    }

    public static function validatePassword(string $plain, string $hash): bool
    {
        return password_verify($plain, $hash);
    }
}
