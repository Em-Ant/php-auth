<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\SessionRepository as IRepo;
use Emant\BrowniePhp\Utils;
use AuthServer\Models\Session;
use AuthServer\Repositories\DataSource;

class SessionRepository implements IRepo
{
    private \PDO $db;

    public function __construct(DataSource $data_source)
    {
        $this->db = $data_source->getDb();
    }

    public function find_by_id(string $id): ?Session
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM sessions WHERE id = :id"
            );
            $statement->bindValue(':id', $id);

            $statement->execute();

            $r = $statement->fetch();

            if (!$r) {
                return null;
            }

            return self::build_from_data($r);
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }

    public function create(
        string $realm_id,
        string $user_id,
        string $acr
    ): ?Session {
        try {
            $uid = Utils::get_guid();

            $q = $this->db->prepare(
                "INSERT INTO sessions (
          'id', 'realm_id', 'user_id', 'acr'
        ) VALUES (:id, :realm_id, :user_id, :acr)"
            );

            $q->bindValue(':id', $uid);
            $q->bindValue(':realm_id', $realm_id);
            $q->bindValue(':user_id', $user_id);
            $q->bindValue(':acr', $acr);

            $q->execute();

            return $this->find_by_id($uid);
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }

    public function refresh(
        string $id
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE sessions 
      SET updated_at=:updated_at
      WHERE id=:id"
            );
            $q->bindValue(':updated_at', gmdate('Y-m-d H:i:s'));
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return false;
        }
    }

    public function set_expired(
        string $id
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE sessions 
      SET status='EXPIRED' 
      WHERE id = :id"
            );
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return false;
        }
    }

    private static function build_from_data(array $r): Session
    {
        return new Session(
            $r['id'],
            $r['realm_id'],
            $r['user_id'],
            $r['acr'],
            $r['created_at'],
            $r['updated_at'],
            $r['status']
        );
    }
}
