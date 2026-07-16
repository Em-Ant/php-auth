<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

class MigrationRepository
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
        $this->ensureTableExists();
    }

    public function getDb(): \PDO
    {
        return $this->db;
    }

    public function ensureTableExists(): void
    {
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS _migrations (
                version    INTEGER PRIMARY KEY,
                name       TEXT NOT NULL,
                checksum   TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
            )
        ');
    }

    public function getApplied(): array
    {
        $stmt = $this->db->query('SELECT version, name, checksum, applied_at FROM _migrations ORDER BY version ASC');
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function getAppliedVersions(): array
    {
        return $this->db->query('SELECT version FROM _migrations ORDER BY version ASC')
            ->fetchAll(\PDO::FETCH_COLUMN);
    }

    public function isApplied(int $version): bool
    {
        $stmt = $this->db->prepare('SELECT 1 FROM _migrations WHERE version = ?');
        $stmt->execute([$version]);
        return (bool) $stmt->fetchColumn();
    }

    public function add(int $version, string $name, string $checksum): void
    {
        $stmt = $this->db->prepare('INSERT INTO _migrations (version, name, checksum) VALUES (?, ?, ?)');
        $stmt->execute([$version, $name, $checksum]);
    }

    public function remove(int $version): void
    {
        $stmt = $this->db->prepare('DELETE FROM _migrations WHERE version = ?');
        $stmt->execute([$version]);
    }

    public function getLatestVersion(): ?int
    {
        $val = $this->db->query('SELECT MAX(version) FROM _migrations')->fetchColumn();
        return $val !== false && $val !== null ? (int) $val : null;
    }

    public function getLastApplied(int $count): array
    {
        $sql = 'SELECT version, name, checksum, applied_at FROM _migrations ORDER BY version DESC LIMIT ?';
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$count]);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }
}
