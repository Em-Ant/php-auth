<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/user_repository.php';

class UserRepository implements IUser
{
  private \PDO $db;

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
  }

  public function findByEmail(string $email): ?User
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM users WHERE email = :email"
      );
      $statement->bindValue(':email', $email);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) return null;

      return new User(
        $r['id'],
        $r['email'],
        $r['password'],
        $r['scopes'],
        \DateTime::createFromFormat('Y-m-d H:i:s', $r['created_at']),
        $r['valid'] == 'TRUE'
      );
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }
}
