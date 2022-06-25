<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

class DataSource
{
  private static $instance;

  private $db;

  private function __construct()
  {
    $this->db = new \PDO('sqlite:db/data.db', '', '', array(
      \PDO::ATTR_EMULATE_PREPARES => false,
      \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
      \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC
    ));;
  }

  public static function getInstance(): DataSource
  {
    if (self::$instance == null) {
      self::$instance = new DataSource();
    }
    return self::$instance;
  }

  public function getDb(): \PDO
  {
    return $this->db;
  }
}
