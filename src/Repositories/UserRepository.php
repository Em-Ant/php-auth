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
     * independent of limit/offset. `$q` is a bound LIKE pattern from
     * ValidatesAdminInput::searchTerm: email is the preferred (indexed)
     * branch, name is the fallback filter. Only submitted filters become
     * WHERE clauses, so the planner can SEARCH the realm/email indexes
     * instead of scanning; values are always bound, never concatenated.
     *
     * @return array{items: User[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset, ?string $q = null): array
    {
        [$where, $params] = self::searchFilter($realmId, $q);

        $statement = $this->db->prepare(
            "SELECT *
             FROM users
             $where
             ORDER BY email
             LIMIT :limit OFFSET :offset"
        );
        self::bindFilterParams($statement, $params);
        self::bindPageParams($statement, $limit, $offset);

        try {
            $statement->execute();
            $rows = $statement->fetchAll();

            return [
                'items' => array_map(fn(array $r) => $this->buildFromData($r), $rows),
                'total' => $this->countFilter($where, $params),
            ];
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list users', 0, $e);
        }
    }

    /**
     * Shared WHERE builder for the listing and its total: only submitted
     * filters become clauses, so the planner can SEARCH the realm/email
     * indexes instead of scanning. Fragments are static; values stay bound.
     *
     * @return array{0: string, 1: array<string, string>}
     */
    private static function searchFilter(?string $realmId, ?string $q): array
    {
        $conditions = [];
        $params = [];
        if ($realmId !== null) {
            $conditions[] = 'realm_id = :realm_id';
            $params[':realm_id'] = $realmId;
        }
        if ($q !== null) {
            $conditions[] = "(email LIKE :q ESCAPE '\\' OR name LIKE :q ESCAPE '\\')";
            $params[':q'] = $q;
        }

        return [$conditions === [] ? '' : 'WHERE ' . implode(' AND ', $conditions), $params];
    }

    /**
     * @param array<string, string> $params
     */
    private static function bindFilterParams(\PDOStatement $statement, array $params): void
    {
        foreach ($params as $name => $value) {
            $statement->bindValue($name, $value, \PDO::PARAM_STR);
        }
    }

    /**
     * @param array<string, string> $params
     */
    private function countFilter(string $where, array $params): int
    {
        try {
            $statement = $this->db->prepare("SELECT COUNT(*) FROM users $where");
            self::bindFilterParams($statement, $params);
            $statement->execute();

            return (int) $statement->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to count users', 0, $e);
        }
    }

    public function create(User $user): User
    {
        try {
            $id = $user->getId() !== '' ? $user->getId() : getGuid();

            $statement = $this->db->prepare(
                "INSERT INTO users (id, realm_id, name, email, email_verified, password, valid)
                 VALUES (:id, :realm_id, :name, :email, :email_verified, :password, :valid)"
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
                    email_verified = :email_verified,
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
            ':email_verified' => $user->getEmailVerified() ? 1 : 0,
            ':password' => $user->getPassword(),
            ':valid' => $user->getValid() ? 1 : 0,
        ];
    }

    /**
     * Accepts both boolean conventions found on disk: the integer 1/0 one and
     * the legacy 'TRUE'/'FALSE' strings written before migration 007, so rows
     * not yet transformed still load correctly.
     */
    private static function readValid(int|string $value): bool
    {
        return $value === 'TRUE' || $value === 1 || $value === '1';
    }

    private static function readEmailVerified(int|string $value): bool
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
            self::readEmailVerified($r['email_verified']),
        );
    }
}
