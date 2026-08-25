<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;

use function AuthServer\getGuid;

class UserRepository implements IUser
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findAll(?string $realmId = null): array
    {
        try {
            if ($realmId === null) {
                $statement = $this->db->query(
                    "SELECT * FROM users ORDER BY email"
                );
                $rows = $statement->fetchAll();
            } else {
                $statement = $this->db->prepare(
                    "SELECT * FROM users WHERE realm_id = :realm_id ORDER BY email"
                );
                $statement->execute([':realm_id' => $realmId]);
                $rows = $statement->fetchAll();
            }

            return array_map(fn(array $r) => $this->buildFromData($r), $rows);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list users', 0, $e);
        }
    }

    public function create(User $user): User
    {
        try {
            $id = $user->getId() !== '' ? $user->getId() : getGuid();

            $statement = $this->db->prepare(
                "INSERT INTO users (id, realm_id, name, email, password, valid)
                 VALUES (:id, :realm_id, :name, :email, :password, :valid)"
            );
            $statement->execute(self::userParams($user, $id));

            return $this->findById($id) ?? $user;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create user', 0, $e);
        }
    }

    public function update(User $user): bool
    {
        try {
            $statement = $this->db->prepare(
                "UPDATE users SET
                    realm_id = :realm_id,
                    name = :name,
                    email = :email,
                    password = :password,
                    valid = :valid
                WHERE id = :id"
            );
            return $statement->execute(self::userParams($user, $user->getId()));
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to update user', 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM users WHERE id = :id"
            );
            return $statement->execute([':id' => $id]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to delete user', 0, $e);
        }
    }

    public function countByRealmId(string $realmId): int
    {
        try {
            $statement = $this->db->prepare(
                "SELECT COUNT(*) FROM users WHERE realm_id = :realm_id"
            );
            $statement->execute([':realm_id' => $realmId]);
            return (int) $statement->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to count users for realm', 0, $e);
        }
    }

    public function findById(string $id): ?User
    {
        $r = $this->fetchOne(
            "SELECT * FROM users WHERE id = :id",
            [':id' => $id],
            "failed to load user by id $id"
        );

        return $r === null ? null : $this->buildFromData($r);
    }

    public function findByEmailAndRealmId(string $email, string $realm_id): ?User
    {
        $r = $this->fetchOne(
            "SELECT * FROM users WHERE email = :email AND realm_id = :realm_id",
            [':email' => $email, ':realm_id' => $realm_id],
            "failed to load user by email $email and realm $realm_id"
        );

        return $r === null ? null : $this->buildFromData($r);
    }

    private function fetchOne(string $sql, array $params, string $errorMessage): ?array
    {
        try {
            $statement = $this->db->prepare($sql);
            $statement->execute($params);

            $r = $statement->fetch();

            return $r === false ? null : $r;
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }

    private static function userParams(User $user, string $id): array
    {
        return [
            ':id' => $id,
            ':realm_id' => $user->getRealmId(),
            ':name' => $user->getName(),
            ':email' => $user->getEmail(),
            ':password' => $user->getPassword(),
            ':valid' => $user->getValid() ? 'TRUE' : 'FALSE',
        ];
    }

    private function buildFromData(array $r): User
    {
        return new User(
            $r['id'],
            $r['realm_id'],
            $r['name'],
            $r['email'],
            $r['password'],
            $r['created_at'],
            $r['valid'] === 'TRUE',
        );
    }
}
