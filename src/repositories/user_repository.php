<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;
use AuthServer\Repositories\DataSource;

class UserRepository implements IUser
{
    private \PDO $db;

    public function __construct(DataSource $data_source)
    {
        $this->db = $data_source->getDb();
    }

    public function findById(string $id): ?User
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM users WHERE id = :id"
            );
            $statement->bindValue(':id', $id);

            $statement->execute();

            $r = $statement->fetch();

            if (!$r) {
                return null;
            }

            return new User(
                $r['id'],
                $r['realm_id'],
                $r['name'],
                $r['email'],
                $r['password'],
                $r['scope'],
                $r['created_at'],
                $r['valid'] == 'TRUE'
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
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

            if (!$r) {
                return null;
            }

            return new User(
                $r['id'],
                $r['realm_id'],
                $r['name'],
                $r['email'],
                $r['password'],
                $r['scope'],
                $r['created_at'],
                $r['valid'] == 'TRUE'
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }
}
