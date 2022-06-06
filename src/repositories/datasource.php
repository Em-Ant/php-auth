<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

class DataSource
{
  private static $instance;

  private $db;

  private function __construct()
  {
    $this->db = new \SQLite3('db/data.db');
  }

  public static function getInstance(): DataSource
  {
    if (self::$instance == null) {
      self::$instance = new DataSource();
    }
    return self::$instance;
  }

  public function getDb(): \Sqlite3
  {
    return $this->db;
  }
}
