<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\MigrationRepository;
use AuthServer\Services\MigrationRunner;
use PHPUnit\Framework\TestCase;

abstract class RepositoryTestCase extends TestCase
{
    protected static DataSource $dataSource;
    protected static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = new \PDO('sqlite::memory:', '', '', [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        self::$pdo->exec('PRAGMA foreign_keys = ON');

        $migrationRepo = new MigrationRepository(self::$pdo);
        $runner = new MigrationRunner(
            $migrationRepo,
            __DIR__ . '/../../db/migrations/'
        );
        $runner->migrate();

        $seed = file_get_contents(__DIR__ . '/../../db/seed.sql');
        self::$pdo->exec($seed);

        DataSource::createInstance(self::$pdo);
        self::$dataSource = DataSource::getInstance();
    }
}
