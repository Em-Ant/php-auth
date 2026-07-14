<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

class DataSource
{
    private static $instance;
    private static ?\PDO $testPdo = null;

    private $db;

    private function __construct()
    {
        if (self::$testPdo !== null) {
            $this->db = self::$testPdo;
            return;
        }
        $dbPath = dirname(__DIR__, 2) . '/db/data.db';
        $this->db = new \PDO("sqlite:$dbPath", '', '', array(
          \PDO::ATTR_EMULATE_PREPARES => false,
          \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
          \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC
        ));
    }

    public static function createInstance(\PDO $pdo): void
    {
        self::$testPdo = $pdo;
        self::$instance = null;
    }

    public static function getInstance(): DataSource
    {
        if (self::$instance === null) {
            self::$instance = new DataSource();
        }
        return self::$instance;
    }

    public function getDb(): \PDO
    {
        return $this->db;
    }
}
