<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\Database;
use PHPUnit\Framework\TestCase;

class DatabaseTest extends TestCase
{
    public function testForeignKeyPragmaIsEnabled(): void
    {
        $pdo = Database::connect('sqlite::memory:');

        $foreignKeys = (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn();

        self::assertSame(1, $foreignKeys);
    }

    public function testForeignKeyViolationsAreRejected(): void
    {
        $pdo = Database::connect('sqlite::memory:');

        $pdo->exec('CREATE TABLE fk_parent (id VARCHAR(36) PRIMARY KEY)');
        $pdo->exec(
            'CREATE TABLE fk_child (
                id VARCHAR(36) PRIMARY KEY,
                parent_id VARCHAR(36) NOT NULL,
                FOREIGN KEY (parent_id) REFERENCES fk_parent(id)
            )'
        );

        $this->expectException(\PDOException::class);
        $this->expectExceptionMessageMatches('/constraint/i');

        $pdo->prepare('INSERT INTO fk_child (id, parent_id) VALUES (:id, :parent_id)')->execute([
            ':id' => 'b0000000-0000-4000-8000-000000000001',
            ':parent_id' => 'b0000000-0000-4000-8000-000000000002',
        ]);
    }
}
