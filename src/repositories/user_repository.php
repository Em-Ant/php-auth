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
                $r['realm_roles'],
                $r['created_at'],
                $r['valid'] == 'TRUE'
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }

    public function findByEmailAndRealmId(string $email, string $realm_id): ?User
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM users WHERE email = :email AND realm_id = :realm_id"
            );
            $statement->bindValue(':email', $email);
            $statement->bindValue(':realm_id', $realm_id);

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
                $r['realm_roles'],
                $r['created_at'],
                $r['valid'] == 'TRUE'
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }
}
