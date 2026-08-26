<?php

declare(strict_types=1);

namespace AuthServer\Services;

final class Database
{
    public static function connect(string $dsn): \PDO
    {
        $pdo = new \PDO($dsn, '', '', [
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);

        // SQLite defaults to FKs OFF per connection. The schema (roles,
        // user_role_assignments, client_scope_roles) relies on them for
        // integrity and cascade deletes; tests enable it in their own
        // bootstraps, so this is also what keeps test/prod parity.
        $pdo->exec('PRAGMA foreign_keys = ON');

        return $pdo;
    }
}
