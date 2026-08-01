<?php

declare(strict_types=1);

namespace AuthServer\Services;

final class Database
{
    public static function connect(string $dsn): \PDO
    {
        return new \PDO($dsn, '', '', [
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);
    }
}
