<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\LoginRepository;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Models\Client;

use function AuthServer\formatSqlDatetime;
use function AuthServer\getGuid;
use function AuthServer\sqlNow;

/**
 * Owns the admin write path for clients: realm lookup, duplicate detection,
 * public/confidential secret invariants, secret hashing, and the guarded
 * cascade delete (active logins + offline sessions). Controllers stay thin
 * adapters over this service.
 */
class ClientAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly ClientRepository $clients,
        private readonly RealmRepository $realms,
        private readonly LoginRepository $logins,
        private readonly OfflineSessionRepository $offlineSessions,
        private readonly SecretsService $secretsService,
    ) {
    }

    /**
     * @param array{
     *     name: string,
     *     uri: string,
     *     require_auth: bool,
     *     client_secret?: mixed,
     *     scope?: string|null,
     * } $params
     */
    public function create(array $params, string $realmId): Client
    {
        if ($this->realms->findById($realmId) === null) {
            throw new ValidationFailed("unknown realm '$realmId'");
        }

        $requireAuth = $params['require_auth'];
        $secretProvided = array_key_exists('client_secret', $params) && $params['client_secret'] !== null;
        // Invariant check on the raw value before any hashing, matching
        // the update path: '' counts as "no secret" and surfaces as 409,
        // and a rejected request costs no argon2 work.
        self::assertPublicHasNoSecret($requireAuth, $secretProvided);
        self::assertConfidentialHasSecret($requireAuth, $params['client_secret'] ?? null);

        $clientSecret = $secretProvided ? $this->hashSecret($params['client_secret']) : null;

        if ($this->findDuplicate($params['name'], $params['uri'], null) !== null) {
            throw new ConflictException("client '{$params['name']}' with this uri already exists");
        }

        $client = new Client(
            getGuid(),
            $params['name'],
            $realmId,
            $clientSecret,
            $params['uri'],
            $requireAuth,
            sqlNow(),
            $params['scope'] ?? null
        );

        return $this->clients->create($client);
    }

    /**
     * @param array{
     *     name: string,
     *     uri: string,
     *     realm_id: string,
     *     require_auth: bool,
     *     client_secret?: mixed,
     *     scope?: string|null,
     * } $params
     */
    public function update(Client $existing, array $params): Client
    {
        if ($this->findDuplicate($params['name'], $params['uri'], $existing->getId()) !== null) {
            throw new ConflictException("client '{$params['name']}' with this uri already exists");
        }

        $realmId = $params['realm_id'];
        if ($this->realms->findById($realmId) === null) {
            throw new ValidationFailed("unknown realm '$realmId'");
        }

        $newRequireAuth = $params['require_auth'];
        $secretProvided = array_key_exists('client_secret', $params) && $params['client_secret'] !== null;

        // Invariant checks run before any hashing: a rejected request
        // costs no argon2 work and surfaces as 409, not as a value error.
        if (!$newRequireAuth) {
            // A secret in a demotion request is contradictory input; an
            // existing secret (or a legacy empty-string hash) is cleared
            // so 'public ⇒ no secret' stays honest. It can be re-issued
            // on a later promotion.
            self::assertPublicHasNoSecret(false, $secretProvided);
            $newSecret = null;
        } else {
            // Promotion to confidential requires the secret in the same
            // call: a confidential client without one cannot authenticate
            // at the token endpoint.
            self::assertConfidentialHasSecret(
                $newRequireAuth,
                $secretProvided ? $params['client_secret'] : $existing->getClientSecret()
            );
            $newSecret = $secretProvided
                ? $this->hashSecret($params['client_secret'])
                : $existing->getClientSecret();
        }

        $client = new Client(
            $existing->getId(),
            $params['name'],
            $realmId,
            $newSecret,
            $params['uri'],
            $newRequireAuth,
            formatSqlDatetime($existing->getCreatedAt()),
            $params['scope'] ?? null
        );

        $this->clients->update($client);

        return $client;
    }

    public function delete(string $clientId): void
    {
        $this->transact(function () use ($clientId): void {
            if ($this->logins->countActiveByClientId($clientId) > 0) {
                throw new ConflictException("client '$clientId' still has active logins");
            }

            if ($this->offlineSessions->countActiveByClientId($clientId) > 0) {
                throw new ConflictException("client '$clientId' still has active offline sessions");
            }

            // Remove the (already expired) offline grants so the FK does not
            // block the delete and no orphan rows survive the client.
            $this->offlineSessions->deleteByClientId($clientId);
            $this->clients->delete($clientId);
        });
    }

    private function findDuplicate(string $name, string $uri, ?string $excludeId): ?Client
    {
        $existing = $this->clients->findByName($name);
        if ($existing === null || $existing->getId() === $excludeId) {
            return null;
        }
        return $existing->getUri() === $uri ? $existing : null;
    }

    private function hashSecret(mixed $secret): string
    {
        if (!is_string($secret) || trim($secret) === '') {
            throw new ValidationFailed("'client_secret' must be a non-empty string");
        }
        return $this->secretsService->hashPassword($secret);
    }

    private static function assertConfidentialHasSecret(bool $requireAuth, mixed $secret): void
    {
        // 'null' and the legacy empty-string hash are both "no secret": a
        // confidential client with either can never authenticate. Non-string
        // input is malformed rather than absent — it passes the invariant and
        // is rejected by hashSecret as a value error (400).
        $hasSecret = is_string($secret) ? Client::isSecretPresent($secret) : $secret !== null;
        if ($requireAuth && !$hasSecret) {
            throw new ConflictException("a confidential client requires a 'client_secret'");
        }
    }

    private static function assertPublicHasNoSecret(bool $requireAuth, bool $secretProvided): void
    {
        if (!$requireAuth && $secretProvided) {
            throw new ConflictException("a public client cannot have a 'client_secret'");
        }
    }
}
