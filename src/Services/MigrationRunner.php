<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\MigrationFailed;
use AuthServer\Repositories\MigrationRepository;

class MigrationRunner
{
    private MigrationRepository $repo;
    private string $dir;

    public function __construct(MigrationRepository $repo, string $migrationsDir)
    {
        $this->repo = $repo;
        $this->dir = rtrim($migrationsDir, '/');
    }

    public function migrate(): array
    {
        $applied = [];
        $todo = $this->pending();

        foreach ($todo as $m) {
            $this->runUp($m);
            $applied[] = $m;
        }

        return $applied;
    }

    public function rollback(int $steps = 1): array
    {
        $rolled = [];
        $lastBatch = $this->repo->getLastApplied($steps);

        foreach ($lastBatch as $row) {
            $version = (int) $row['version'];
            $m = $this->findMigrationOrFail($version);
            $this->runDown($m);
            $rolled[] = $m;
        }

        return $rolled;
    }

    public function go(int $targetVersion): array
    {
        $current = $this->repo->getLatestVersion() ?? 0;

        if ($targetVersion > $current) {
            return $this->migrateUpTo($targetVersion);
        }

        if ($targetVersion < $current) {
            return $this->rollbackDownTo($targetVersion);
        }

        return [];
    }

    public function status(): array
    {
        $applied = $this->repo->getApplied();
        $appliedVersions = array_map(fn(array $r) => (int) $r['version'], $applied);
        $all = $this->parseMigrations();

        $result = [];
        foreach ($all as $m) {
            $isApplied = in_array($m->version, $appliedVersions, true);
            $appliedRow = null;
            if ($isApplied) {
                $idx = array_search($m->version, $appliedVersions, true);
                $appliedRow = $applied[$idx];
            }
            $result[] = [
                'version'    => $m->version,
                'name'       => $m->name,
                'applied'    => $isApplied,
                'applied_at' => $appliedRow['applied_at'] ?? null,
                'checksum'   => $appliedRow['checksum'] ?? null,
                'has_down'   => $m->downFile !== null,
            ];
        }

        return $result;
    }

    public function dryRun(): array
    {
        $pending = $this->pending();
        return array_map(fn(Migration $m) => [
            'version' => $m->version,
            'name'    => $m->name,
            'type'    => 'up',
        ], $pending);
    }

    // ---- private helpers ----

    private function pending(): array
    {
        $applied = $this->repo->getAppliedVersions();
        return array_values(
            array_filter(
                $this->parseMigrations(),
                fn(Migration $m) => !in_array($m->version, $applied, true)
            )
        );
    }

    private function migrateUpTo(int $maxVersion): array
    {
        $applied = [];
        foreach ($this->pending() as $m) {
            if ($m->version > $maxVersion) {
                break;
            }
            $this->runUp($m);
            $applied[] = $m;
        }
        return $applied;
    }

    private function rollbackDownTo(int $minVersion): array
    {
        $rolled = [];
        $applied = $this->repo->getApplied();

        foreach (array_reverse($applied) as $row) {
            $version = (int) $row['version'];
            if ($version <= $minVersion) {
                break;
            }
            $m = $this->findMigrationOrFail($version);
            $this->runDown($m);
            $rolled[] = $m;
        }

        return $rolled;
    }

    private function runUp(Migration $m): void
    {
        $sql = file_get_contents($m->upFile);
        if ($sql === false) {
            throw new MigrationFailed("Cannot read {$m->upFile}");
        }

        $checksum = hash('sha256', $sql);

        $this->repo->ensureTableExists();

        try {
            $this->repo->getDb()->beginTransaction();
            $this->repo->getDb()->exec($sql);
            $this->repo->add($m->version, $m->name, $checksum);
            $this->repo->getDb()->commit();
        } catch (\Throwable $e) {
            $this->repo->getDb()->rollBack();
            throw new MigrationFailed(
                "Migration {$m->version}-{$m->name} failed: " . $e->getMessage(),
                0,
                $e
            );
        }
    }

    private function runDown(Migration $m): void
    {
        if ($m->downFile === null) {
            throw new MigrationFailed(
                "Migration {$m->version}-{$m->name} has no down file — cannot rollback"
            );
        }

        $sql = file_get_contents($m->downFile);
        if ($sql === false) {
            throw new MigrationFailed("Cannot read {$m->downFile}");
        }

        try {
            $this->repo->getDb()->beginTransaction();
            $this->repo->getDb()->exec($sql);
            $this->repo->remove($m->version);
            $this->repo->getDb()->commit();
        } catch (\Throwable $e) {
            $this->repo->getDb()->rollBack();
            throw new MigrationFailed(
                "Rollback {$m->version}-{$m->name} failed: " . $e->getMessage(),
                0,
                $e
            );
        }
    }

    private function findMigration(int $version): ?Migration
    {
        foreach ($this->parseMigrations() as $m) {
            if ($m->version === $version) {
                return $m;
            }
        }
        return null;
    }

    private function findMigrationOrFail(int $version): Migration
    {
        $m = $this->findMigration($version);
        if ($m === null) {
            throw new MigrationFailed("Migration file for version {$version} not found");
        }
        return $m;
    }

    private function parseMigrations(): array
    {
        $pattern = $this->dir . '/*.up.sql';
        $files = glob($pattern);
        if ($files === false) {
            return [];
        }

        $migrations = [];
        foreach ($files as $path) {
            $basename = basename($path);
            if (!preg_match('/^(\d+)_(.+)\.up\.sql$/', $basename, $m)) {
                continue;
            }

            $version = (int) $m[1];
            $name = $m[2];
            $downPath = preg_replace('/\.up\.sql$/', '.down.sql', $path);

            $migrations[] = new Migration(
                version: $version,
                name: $name,
                upFile: $path,
                downFile: file_exists($downPath) ? $downPath : null,
            );
        }

        usort($migrations, fn(Migration $a, Migration $b) => $a->version <=> $b->version);

        return $migrations;
    }
}
