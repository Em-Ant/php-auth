<?php

declare(strict_types=1);

namespace AuthServer\Services;

use Emant\BrowniePhp\Utils;

class SecretsService
{
    private array $config;

    public function __construct(?array $config = null)
    {
        $this->config = $config ?? [];
    }

    public function generateCode(): string
    {
        return join('.', [Utils::get_guid(), Utils::get_guid(), Utils::get_guid()]);
    }

    public function hashPassword(string $password): string
    {
        $algo = $this->config['algorithm'] ?? 'argon2id';

        if ($algo === 'argon2id') {
            return password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => $this->config['argon2_memory_cost'] ?? 1024,
                'time_cost' => $this->config['argon2_time_cost'] ?? 2,
                'threads' => $this->config['argon2_threads'] ?? 2,
            ]);
        }

        return password_hash($password, PASSWORD_BCRYPT, [
            'cost' => $this->config['bcrypt_cost'] ?? 12,
        ]);
    }

    public function validatePassword(string $plain, string $hash): bool
    {
        return password_verify($plain, $hash);
    }
}
