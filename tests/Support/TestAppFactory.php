<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use AuthServer\App\AppBuilder;
use AuthServer\Config\Definitions;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Services\Database;
use AuthServer\Services\InMemorySessionCookieHandler;

class TestAppFactory
{
    public static function createApp(array $overrides = []): \Slim\App
    {
        $pdo = Database::connect('sqlite::memory:');

        $pdo->exec('PRAGMA foreign_keys = ON');

        $di = Definitions::get();

        // Override PDO with in-memory SQLite
        $di[\PDO::class] = $pdo;

        // Override session cookie handler for testing
        $di[SessionCookieHandler::class] = \DI\autowire(InMemorySessionCookieHandler::class);

        // Suppress log output during tests
        $overrides['log_settings'] ??= ['print' => false, 'write' => false];

        // Apply any additional overrides
        foreach ($overrides as $key => $value) {
            $di[$key] = $value;
        }

        $container = new \DI\Container($di);

        self::migrateAndSeed($pdo);

        return AppBuilder::create($container);
    }

    private static function migrateAndSeed(\PDO $pdo): void
    {
        // Run migrations on the in-memory database
        $migrationRepo = new \AuthServer\Repositories\MigrationRepository($pdo);
        $runner = new \AuthServer\Services\MigrationRunner(
            $migrationRepo,
            __DIR__ . '/../../migrations/'
        );
        $runner->migrate();

        // Seed data
        $seed = file_get_contents(__DIR__ . '/../../db/seed.sql');
        $pdo->exec($seed);
    }
}
