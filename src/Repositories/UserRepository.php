<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;

use function AuthServer\get_guid;

class UserRepository implements IUser
{
    private \PDO $db;
    private RoleRepository $roles;

    public function __construct(\PDO $db, RoleRepository $roles)
    {
        $this->db = $db;
        $this->roles = $roles;
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
            $id = $user->getId() !== '' ? $user->getId() : get_guid();

            $statement = $this->db->prepare(
                "INSERT INTO users (id, realm_id, name, email, password, valid)
                 VALUES (:id, :realm_id, :name, :email, :password, :valid)"
            );
            $statement->execute(self::userParams($user, $id));

            $this->roles->syncRealmRoles($id, $user->getRealmId(), $user->getRealmRoles());

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
            $ok = $statement->execute(self::userParams($user, $user->getId()));

            $this->roles->syncRealmRoles($user->getId(), $user->getRealmId(), $user->getRealmRoles());

            return $ok;
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

            return $this->buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load user by id $id", 0, $e);
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

            return $this->buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed(
                "failed to load user by email $email and realm $realm_id",
                0,
                $e
            );
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
        $userId = $r['id'];
        $realmId = $r['realm_id'];
        return new User(
            $userId,
            $realmId,
            $r['name'],
            $r['email'],
            $r['password'],
            $this->roles->findRealmRoleNamesByUserId($userId, $realmId),
            $r['created_at'],
            $r['valid'] === 'TRUE',
            $this->roles->findClientRoleNamesByUserId($userId, $realmId),
        );
    }
}
