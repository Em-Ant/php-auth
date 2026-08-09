<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;

class TokenBlacklistRepository
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function add(string $jti, int $exp): bool
    {
        try {
            $q = $this->db->prepare(
                "INSERT OR IGNORE INTO token_blacklist (jti, exp) VALUES (:jti, :exp)"
            );
            $q->bindValue(':jti', $jti);
            $q->bindValue(':exp', $exp);
            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to add token to blacklist', 0, $e);
        }
    }

    public function exists(string $jti): bool
    {
        try {
            $q = $this->db->prepare(
                "SELECT 1 FROM token_blacklist WHERE jti = :jti"
            );
            $q->bindValue(':jti', $jti);
            $q->execute();
            return (bool) $q->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to check token in blacklist', 0, $e);
        }
    }
}
