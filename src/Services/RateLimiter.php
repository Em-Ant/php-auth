<?php

declare(strict_types=1);

namespace AuthServer\Services;

class RateLimiter
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
        $this->ensureTableExists();
    }

    public function isAllowed(string $ip, string $endpoint, int $maxRequests, int $windowSeconds): bool
    {
        $window = (int) (time() / $windowSeconds) * $windowSeconds;

        $existing = $this->db->prepare(
            'SELECT count FROM rate_limits WHERE ip = ? AND endpoint = ? AND window_start = ?'
        );
        $existing->execute([$ip, $endpoint, $window]);
        $row = $existing->fetch(\PDO::FETCH_ASSOC);

        if ($row !== false) {
            if ((int) $row['count'] >= $maxRequests) {
                return false;
            }

            $update = $this->db->prepare(
                'UPDATE rate_limits SET count = count + 1 WHERE ip = ? AND endpoint = ? AND window_start = ?'
            );
            $update->execute([$ip, $endpoint, $window]);
        } else {
            $insert = $this->db->prepare(
                'INSERT INTO rate_limits (ip, endpoint, window_start, count) VALUES (?, ?, ?, 1)'
            );
            $insert->execute([$ip, $endpoint, $window]);
        }

        $this->maybeCleanup();

        return true;
    }

    public function getRemaining(string $ip, string $endpoint, int $maxRequests, int $windowSeconds): int
    {
        $window = (int) (time() / $windowSeconds) * $windowSeconds;

        $stmt = $this->db->prepare(
            'SELECT count FROM rate_limits WHERE ip = ? AND endpoint = ? AND window_start = ?'
        );
        $stmt->execute([$ip, $endpoint, $window]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if ($row === false) {
            return $maxRequests;
        }

        return max(0, $maxRequests - (int) $row['count']);
    }

    public function getRetryAfter(string $ip, string $endpoint, int $windowSeconds): int
    {
        $window = (int) (time() / $windowSeconds) * $windowSeconds;
        return $window + $windowSeconds - time();
    }

    private function ensureTableExists(): void
    {
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip          TEXT NOT NULL,
                endpoint    TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (ip, endpoint, window_start)
            )
        ');
    }

    private function maybeCleanup(): void
    {
        if (random_int(1, 100) <= 5) {
            $cutoff = time() - 3600;
            $this->db->prepare('DELETE FROM rate_limits WHERE window_start < ?')
                ->execute([$cutoff]);
        }
    }
}
