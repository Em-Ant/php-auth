<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use Psr\Log\LoggerInterface;
use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;

class UserRepository implements IUser
{
    private \PDO $db;
    private LoggerInterface $logger;

    public function __construct(\PDO $db, LoggerInterface $logger)
    {
        $this->db = $db;
        $this->logger = $logger;
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
                $r['valid'] === 'TRUE'
            );
        } catch (\PDOException $e) {
            $this->logger->error($e->getMessage());
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
                $r['valid'] === 'TRUE'
            );
        } catch (\PDOException $e) {
            $this->logger->error($e->getMessage());
            return null;
        }
    }
}
