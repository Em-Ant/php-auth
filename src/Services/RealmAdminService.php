<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\Realm;

use function AuthServer\formatSqlDatetime;
use function AuthServer\getGuid;
use function AuthServer\sqlNow;

/**
 * Owns the admin write path for realms: duplicate name detection, key-set
 * existence validation, entity construction and the guarded cascade delete
 * (refuse when clients or users remain). Controllers stay thin adapters.
 */
class RealmAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly RealmRepository $realms,
        private readonly ClientRepository $clients,
        private readonly UserRepository $users,
        private readonly KeyStore $keyStore,
    ) {
    }

    /**
     * @param array{
     *     name: string,
     *     keys_id: string,
     *     refresh_token_expires_in: int,
     *     access_token_expires_in: int,
     *     pending_login_expires_in: int,
     *     authenticated_login_expires_in: int,
     *     session_expires_in: int,
     *     idle_session_expires_in: int,
     *     scope: string,
     *     offline_refresh_token_expires_in: int,
     * } $params
     */
    public function create(array $params): Realm
    {
        $name = $params['name'];
        if ($this->realms->findByName($name) !== null) {
            throw new ConflictException("realm '$name' already exists");
        }

        $this->assertKeysExist($params['keys_id']);

        return $this->realms->create($this->buildRealm(getGuid(), $name, $params, sqlNow()));
    }

    /**
     * @param array{
     *     name: string,
     *     keys_id: string,
     *     refresh_token_expires_in: int,
     *     access_token_expires_in: int,
     *     pending_login_expires_in: int,
     *     authenticated_login_expires_in: int,
     *     session_expires_in: int,
     *     idle_session_expires_in: int,
     *     scope: string,
     *     offline_refresh_token_expires_in: int,
     * } $params
     */
    public function update(Realm $existing, array $params): Realm
    {
        $name = $params['name'];
        if ($this->realms->findByName($name) !== null && $name !== $existing->getName()) {
            throw new ConflictException("realm '$name' already exists");
        }

        $this->assertKeysExist($params['keys_id']);

        $realm = $this->buildRealm($existing->getId(), $name, $params, formatSqlDatetime($existing->getCreatedAt()));
        $this->realms->update($realm);

        return $realm;
    }

    /**
     * @param array{
     *     name: string,
     *     keys_id: string,
     *     refresh_token_expires_in: int,
     *     access_token_expires_in: int,
     *     pending_login_expires_in: int,
     *     authenticated_login_expires_in: int,
     *     session_expires_in: int,
     *     idle_session_expires_in: int,
     *     scope: string,
     *     offline_refresh_token_expires_in: int,
     * } $params
     */
    private function buildRealm(string $id, string $name, array $params, string $createdAt): Realm
    {
        return new Realm(
            $id,
            $name,
            $params['keys_id'],
            $params['refresh_token_expires_in'],
            $params['access_token_expires_in'],
            $params['pending_login_expires_in'],
            $params['authenticated_login_expires_in'],
            $params['session_expires_in'],
            $params['idle_session_expires_in'],
            $params['scope'],
            $createdAt,
            $params['offline_refresh_token_expires_in']
        );
    }

    public function delete(string $realmId): void
    {
        $this->transact(function () use ($realmId): void {
            if ($this->clients->countByRealmId($realmId) > 0 || $this->users->countByRealmId($realmId) > 0) {
                throw new ConflictException("realm '$realmId' still has clients or users");
            }

            $this->realms->delete($realmId);
        });
    }

    private function assertKeysExist(string $keysId): void
    {
        try {
            $this->keyStore->findKeys($keysId);
        } catch (\RuntimeException $e) {
            throw new ValidationFailed("unknown keys_id '$keysId'");
        }
    }
}
