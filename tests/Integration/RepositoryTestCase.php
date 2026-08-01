<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Repositories\MigrationRepository;
use AuthServer\Services\Database;
use AuthServer\Services\MigrationRunner;
use PHPUnit\Framework\TestCase;

abstract class RepositoryTestCase extends TestCase
{
    protected static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = Database::connect('sqlite::memory:');

        self::$pdo->exec('PRAGMA foreign_keys = ON');

        $migrationRepo = new MigrationRepository(self::$pdo);
        $runner = new MigrationRunner(
            $migrationRepo,
            __DIR__ . '/../../migrations/'
        );
        $runner->migrate();

        $seed = file_get_contents(__DIR__ . '/../../db/seed.sql');
        self::$pdo->exec($seed);
    }
}
