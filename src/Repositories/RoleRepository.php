<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\RoleRepository as IRoleRepo;
use AuthServer\Models\Role;

use function AuthServer\get_guid;

class RoleRepository implements IRoleRepo
{
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
            $id = $role->getId() !== '' ? $role->getId() : get_guid();

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

    public function delete(string $id): bool
    {
        try {
            $stmt = $this->db->prepare('DELETE FROM roles WHERE id = :id');
            return $stmt->execute([':id' => $id]);
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

    public function syncRealmRoles(string $userId, string $realmId, array $roleNames): void
    {
        try {
            $this->db->beginTransaction();

            $delete = $this->db->prepare(
                'DELETE FROM user_role_assignments
                 WHERE user_id = :user_id
                   AND role_id IN (SELECT id FROM roles WHERE realm_id = :realm_id AND client_id IS NULL)'
            );
            $delete->execute([':user_id' => $userId, ':realm_id' => $realmId]);

            foreach ($roleNames as $roleName) {
                $roleId = $this->ensureRealmRole($realmId, $roleName);
                $insert = $this->db->prepare(
                    'INSERT OR IGNORE INTO user_role_assignments (user_id, role_id)
                     VALUES (:user_id, :role_id)'
                );
                $insert->execute([':user_id' => $userId, ':role_id' => $roleId]);
            }

            $this->db->commit();
        } catch (\PDOException $e) {
            $this->db->rollBack();
            throw new StorageFailed('failed to sync realm roles', 0, $e);
        }
    }

    private function ensureRealmRole(string $realmId, string $roleName): string
    {
        $insert = $this->db->prepare(
            'INSERT OR IGNORE INTO roles (id, realm_id, client_id, name)
             VALUES (:id, :realm_id, NULL, :name)'
        );
        $insert->execute([
            ':id' => get_guid(),
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
