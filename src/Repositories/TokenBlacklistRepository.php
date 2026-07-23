<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use Psr\Log\LoggerInterface;

class TokenBlacklistRepository
{
    private \PDO $db;
    private LoggerInterface $logger;

    public function __construct(\PDO $db, LoggerInterface $logger)
    {
        $this->db = $db;
        $this->logger = $logger;
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
            $this->logger->error($e->getMessage());
            return false;
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
            $this->logger->error($e->getMessage());
            return false;
        }
    }
}
