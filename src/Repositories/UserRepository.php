<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\UserRepository as IUser;
use AuthServer\Models\User;

use function AuthServer\getGuid;

class UserRepository implements IUser
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Filtered, paged listing. `total` counts all rows matching the filters,
     * independent of limit/offset.
     *
     * @return array{items: User[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset): array
    {
        $statement = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM users
             WHERE (:realm_id IS NULL OR realm_id = :realm_id)
             ORDER BY email
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($statement, ':realm_id', $realmId);
        self::bindPageParams($statement, $limit, $offset);

        return $this->fetchPagedPage(
            $statement,
            fn(array $r) => $this->buildFromData($r),
            'failed to list users'
        );
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
            $statement->execute([':id' => $id]);
            return $statement->rowCount() > 0;
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
            ':valid' => $user->getValid() ? 1 : 0,
        ];
    }

    /**
     * Accepts both boolean conventions found on disk: the integer 1/0 one
     * used since migration 007 and the legacy 'TRUE'/'FALSE' strings it
     * replaced, so rows not yet transformed still load correctly.
     */
    private static function readValid(int|string $value): bool
    {
        return $value === 'TRUE' || $value === 1 || $value === '1';
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
            self::readValid($r['valid']),
        );
    }
}
