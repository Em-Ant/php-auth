<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\RoleRepository as IRoleRepo;
use AuthServer\Models\Role;
use AuthServer\Models\ScopeRoleMapping;

use function AuthServer\getGuid;

class RoleRepository implements IRoleRepo
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findById(string $id): ?Role
    {
        try {
            $stmt = $this->db->prepare('SELECT * FROM roles WHERE id = :id');
            $stmt->bindValue(':id', $id);
            $stmt->execute();
            $r = $stmt->fetch();

            return $r ? self::buildFromData($r) : null;
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load role by id $id", 0, $e);
        }
    }

    public function findAll(?string $realmId = null, ?string $clientId = null): array
    {
        try {
            if ($realmId !== null && $clientId !== null) {
                $stmt = $this->db->prepare(
                    'SELECT * FROM roles WHERE realm_id = :realm_id AND client_id = :client_id ORDER BY name'
                );
                $stmt->execute([':realm_id' => $realmId, ':client_id' => $clientId]);
            } elseif ($realmId !== null) {
                $stmt = $this->db->prepare(
                    'SELECT * FROM roles WHERE realm_id = :realm_id ORDER BY name'
                );
                $stmt->execute([':realm_id' => $realmId]);
            } elseif ($clientId !== null) {
                $stmt = $this->db->prepare(
                    'SELECT * FROM roles WHERE client_id = :client_id ORDER BY name'
                );
                $stmt->execute([':client_id' => $clientId]);
            } else {
                $stmt = $this->db->query('SELECT * FROM roles ORDER BY name');
            }

            return array_map(fn(array $r) => self::buildFromData($r), $stmt->fetchAll());
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list roles', 0, $e);
        }
    }

    public function create(Role $role): Role
    {
        try {
            $id = $role->getId() !== '' ? $role->getId() : getGuid();

            $stmt = $this->db->prepare(
                'INSERT INTO roles (id, realm_id, client_id, name, description)
                 VALUES (:id, :realm_id, :client_id, :name, :description)'
            );
            $stmt->execute([
                ':id' => $id,
                ':realm_id' => $role->getRealmId(),
                ':client_id' => $role->getClientId(),
                ':name' => $role->getName(),
                ':description' => $role->getDescription(),
            ]);

            return $this->findById($id) ?? $role;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create role', 0, $e);
        }
    }

    public function update(Role $role): bool
    {
        try {
            $stmt = $this->db->prepare(
                'UPDATE roles SET name = :name, description = :description
                 WHERE id = :id'
            );
            return $stmt->execute([
                ':name' => $role->getName(),
                ':description' => $role->getDescription(),
                ':id' => $role->getId(),
            ]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to update role', 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $stmt = $this->db->prepare('DELETE FROM roles WHERE id = :id');
            $stmt->execute([':id' => $id]);

            return $stmt->rowCount() > 0;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to delete role', 0, $e);
        }
    }

    public function findRealmRoleNamesByUserId(string $userId, string $realmId): array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT r.name FROM user_role_assignments ura
                 JOIN roles r ON r.id = ura.role_id
                 WHERE ura.user_id = :user_id AND r.realm_id = :realm_id AND r.client_id IS NULL
                 ORDER BY r.name'
            );
            $stmt->execute([':user_id' => $userId, ':realm_id' => $realmId]);

            return $stmt->fetchAll(\PDO::FETCH_COLUMN);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to load realm roles', 0, $e);
        }
    }

    public function findClientRoleNamesByUserId(string $userId, string $realmId): array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT c.name AS client_name, r.name AS role_name
                 FROM user_role_assignments ura
                 JOIN roles r ON r.id = ura.role_id
                 JOIN clients c ON c.id = r.client_id
                 WHERE ura.user_id = :user_id AND r.realm_id = :realm_id AND r.client_id IS NOT NULL
                 ORDER BY c.name, r.name'
            );
            $stmt->execute([':user_id' => $userId, ':realm_id' => $realmId]);

            $result = [];
            foreach ($stmt->fetchAll() as $row) {
                $result[$row['client_name']][] = $row['role_name'];
            }
            return $result;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to load client roles', 0, $e);
        }
    }

    public function findByUserId(string $userId): array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT r.* FROM roles r
                 JOIN user_role_assignments ura ON ura.role_id = r.id
                 WHERE ura.user_id = :user_id
                 ORDER BY r.name'
            );
            $stmt->execute([':user_id' => $userId]);

            return array_map(fn(array $r) => self::buildFromData($r), $stmt->fetchAll());
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to load roles for user', 0, $e);
        }
    }

    public function findScopeRoleMappings(string $clientId): array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT r.id AS role_id, csr.scope, r.name AS role_name, c.name AS role_client_name, csr.required
                 FROM client_scope_roles csr
                 JOIN roles r ON r.id = csr.role_id
                 LEFT JOIN clients c ON c.id = r.client_id
                 WHERE csr.client_id = :client_id
                 ORDER BY csr.scope, r.name'
            );
            $stmt->execute([':client_id' => $clientId]);

            $grouped = [];
            foreach ($stmt->fetchAll() as $row) {
                $grouped[$row['scope']][] = new ScopeRoleMapping(
                    $row['role_id'],
                    $row['scope'],
                    $row['role_name'],
                    $row['role_client_name'],
                    (bool) $row['required'],
                );
            }
            return $grouped;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to load scope role mappings', 0, $e);
        }
    }

    /**
     * Replace the realm-role assignments for a user. Participates in an
     * already-open transaction when the caller owns one (re-entrant), and
     * only opens its own otherwise.
     */
    public function syncRealmRoles(string $userId, string $realmId, array $roleNames): void
    {
        $ownsTransaction = !$this->db->inTransaction();

        if ($ownsTransaction) {
            $this->db->beginTransaction();
        }

        try {
            $this->deleteRealmRoleAssignments($userId, $realmId);

            foreach ($roleNames as $roleName) {
                $roleId = $this->ensureRealmRole($realmId, $roleName);
                $insert = $this->db->prepare(
                    'INSERT OR IGNORE INTO user_role_assignments (user_id, role_id)
                     VALUES (:user_id, :role_id)'
                );
                $insert->execute([':user_id' => $userId, ':role_id' => $roleId]);
            }

            if ($ownsTransaction) {
                $this->db->commit();
            }
        } catch (\PDOException $e) {
            if ($ownsTransaction) {
                $this->db->rollBack();
            }
            throw new StorageFailed('failed to sync realm roles', 0, $e);
        }
    }

    private function deleteRealmRoleAssignments(string $userId, string $realmId): void
    {
        $delete = $this->db->prepare(
            'DELETE FROM user_role_assignments
             WHERE user_id = :user_id
               AND role_id IN (SELECT id FROM roles WHERE realm_id = :realm_id AND client_id IS NULL)'
        );
        $delete->execute([':user_id' => $userId, ':realm_id' => $realmId]);
    }

    private function ensureRealmRole(string $realmId, string $roleName): string
    {
        $insert = $this->db->prepare(
            'INSERT OR IGNORE INTO roles (id, realm_id, client_id, name)
             VALUES (:id, :realm_id, NULL, :name)'
        );
        $insert->execute([
            ':id' => getGuid(),
            ':realm_id' => $realmId,
            ':name' => $roleName,
        ]);

        $select = $this->db->prepare(
            'SELECT id FROM roles WHERE realm_id = :realm_id AND client_id IS NULL AND name = :name'
        );
        $select->execute([':realm_id' => $realmId, ':name' => $roleName]);

        $id = $select->fetchColumn();
        return $id !== false ? (string) $id : '';
    }

    public function searchAll(?string $realmId, ?string $clientId, int $limit, int $offset): array
    {
        $stmt = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM roles
             WHERE (:realm_id IS NULL OR realm_id = :realm_id)
               AND (:client_id IS NULL OR client_id = :client_id)
             ORDER BY name
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($stmt, ':realm_id', $realmId);
        self::bindNullableString($stmt, ':client_id', $clientId);
        self::bindPageParams($stmt, $limit, $offset);

        return $this->fetchPagedPage(
            $stmt,
            fn(array $r) => self::buildFromData($r),
            'failed to list roles'
        );
    }

    public function countUsersByRoleId(string $roleId): int
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT COUNT(*) FROM user_role_assignments WHERE role_id = :role_id'
            );
            $stmt->execute([':role_id' => $roleId]);
            return (int) $stmt->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to count users for role', 0, $e);
        }
    }

    public function assignRoleToUser(string $userId, string $roleId): void
    {
        try {
            $stmt = $this->db->prepare(
                'INSERT OR IGNORE INTO user_role_assignments (user_id, role_id)
                 VALUES (:user_id, :role_id)'
            );
            $stmt->execute([':user_id' => $userId, ':role_id' => $roleId]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to assign role to user', 0, $e);
        }
    }

    public function removeRoleFromUser(string $userId, string $roleId): bool
    {
        try {
            $stmt = $this->db->prepare(
                'DELETE FROM user_role_assignments
                 WHERE user_id = :user_id AND role_id = :role_id'
            );
            $stmt->execute([':user_id' => $userId, ':role_id' => $roleId]);
            return $stmt->rowCount() > 0;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to remove role from user', 0, $e);
        }
    }

    public function userHasRole(string $userId, string $roleId): bool
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT 1 FROM user_role_assignments
                 WHERE user_id = :user_id AND role_id = :role_id'
            );
            $stmt->execute([':user_id' => $userId, ':role_id' => $roleId]);
            return $stmt->fetch() !== false;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to check user role assignment', 0, $e);
        }
    }

    public function createScopeRoleMapping(string $clientId, string $scope, string $roleId, bool $required): void
    {
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO client_scope_roles (client_id, scope, role_id, required)
                 VALUES (:client_id, :scope, :role_id, :required)'
            );
            $stmt->execute([
                ':client_id' => $clientId,
                ':scope' => $scope,
                ':role_id' => $roleId,
                ':required' => $required ? 1 : 0,
            ]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create scope role mapping', 0, $e);
        }
    }

    public function updateScopeRoleMapping(string $clientId, string $scope, string $roleId, bool $required): bool
    {
        try {
            $stmt = $this->db->prepare(
                'UPDATE client_scope_roles
                 SET required = :required
                 WHERE client_id = :client_id AND scope = :scope AND role_id = :role_id'
            );
            $stmt->execute([
                ':required' => $required ? 1 : 0,
                ':client_id' => $clientId,
                ':scope' => $scope,
                ':role_id' => $roleId,
            ]);
            return $stmt->rowCount() > 0;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to update scope role mapping', 0, $e);
        }
    }

    public function deleteScopeRoleMapping(string $clientId, string $scope, string $roleId): bool
    {
        try {
            $stmt = $this->db->prepare(
                'DELETE FROM client_scope_roles
                 WHERE client_id = :client_id AND scope = :scope AND role_id = :role_id'
            );
            $stmt->execute([
                ':client_id' => $clientId,
                ':scope' => $scope,
                ':role_id' => $roleId,
            ]);
            return $stmt->rowCount() > 0;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to delete scope role mapping', 0, $e);
        }
    }

    public function findScopeRoleMapping(string $clientId, string $scope, string $roleId): ?array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT * FROM client_scope_roles
                 WHERE client_id = :client_id AND scope = :scope AND role_id = :role_id'
            );
            $stmt->execute([
                ':client_id' => $clientId,
                ':scope' => $scope,
                ':role_id' => $roleId,
            ]);
            $row = $stmt->fetch();
            return $row !== false ? $row : null;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to load scope role mapping', 0, $e);
        }
    }

    private static function buildFromData(array $r): Role
    {
        $utc = new \DateTimeZone('UTC');
        return new Role(
            $r['id'],
            $r['realm_id'],
            $r['client_id'] ?? null,
            $r['name'],
            $r['description'] ?? null,
            \DateTime::createFromFormat('Y-m-d H:i:s', $r['created_at'], $utc),
        );
    }
}
