<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\LoginRepository;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Models\Client;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\SecretsService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;
use function AuthServer\getGuid;
use function AuthServer\sqlNow;

class ClientsController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly RealmRepository $realms,
        private readonly LoginRepository $logins,
        private readonly OfflineSessionRepository $offlineSessions,
        private readonly SecretsService $secretsService,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $realmId = isset($query['realm_id']) && $query['realm_id'] !== ''
            ? $query['realm_id']
            : null;

        return JsonResponse::create($response, [
            'clients' => array_map(
                fn(Client $client) => self::toArray($client),
                $this->clients->findAll($realmId)
            ),
        ]);
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);

            $name = $this->requiredString($body, 'name');
            $realmId = $this->requiredString($body, 'realm_id');
            $uri = $this->requiredString($body, 'uri');

            if ($this->realms->findById($realmId) === null) {
                throw new ValidationFailed("unknown realm '$realmId'");
            }

            $clientSecret = $this->optionalSecret($body);
            if ($this->findDuplicate($name, $uri, null) !== null) {
                throw new ConflictException("client '$name' with this uri already exists");
            }

            $client = new Client(
                getGuid(),
                $name,
                $realmId,
                $clientSecret,
                $uri,
                $this->optionalBool($body, 'require_auth', false),
                sqlNow(),
                $this->optionalString($body, 'scope', null)
            );

            $this->clients->create($client);

            return JsonResponse::create($response, self::toArray($client), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $client = $this->findClientOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, self::toArray($client));
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $existing = $this->findClientOrFail($request, $request->getAttribute('id'));

            $body = (array) ($request->getParsedBody() ?? []);

            $name = $this->optionalString($body, 'name', null) ?? $existing->getName();
            $uri = $this->optionalString($body, 'uri', null) ?? $existing->getUri();

            if ($this->findDuplicate($name, $uri, $existing->getId()) !== null) {
                throw new ConflictException("client '$name' with this uri already exists");
            }

            $realmId = $this->optionalString($body, 'realm_id', null) ?? $existing->getRealmId();
            if ($this->realms->findById($realmId) === null) {
                throw new ValidationFailed("unknown realm '$realmId'");
            }

            $clientSecret = array_key_exists('client_secret', $body) && $body['client_secret'] !== null
                ? $this->hashSecret($body['client_secret'])
                : $existing->getClientSecret();

            $client = new Client(
                $existing->getId(),
                $name,
                $realmId,
                $clientSecret,
                $uri,
                $this->optionalBool($body, 'require_auth', $existing->requiresAuth()),
                formatSqlDatetime($existing->getCreatedAt()),
                $this->optionalString($body, 'scope', $existing->getScopeString())
            );

            $this->clients->update($client);

            return JsonResponse::create($response, self::toArray($client));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findClientOrFail($request, $id);

        if ($this->logins->countActiveByClientId($id) > 0) {
            throw new ConflictException("client '$id' still has active logins");
        }

        if ($this->offlineSessions->countActiveByClientId($id) > 0) {
            throw new ConflictException("client '$id' still has active offline sessions");
        }

        // Remove the (already expired) offline grants so the FK does not block
        // the delete and no orphan rows survive the client.
        $this->offlineSessions->deleteByClientId($id);
        $this->clients->delete($id);

        return $response->withStatus(204);
    }

    private function findClientOrFail(ServerRequestInterface $request, string $id): Client
    {
        $client = $this->clients->findById($id);
        if ($client === null) {
            throw new HttpNotFoundException($request, "client '$id' not found");
        }
        return $client;
    }

    private function findDuplicate(string $name, string $uri, ?string $excludeId): ?Client
    {
        $existing = $this->clients->findByName($name);
        if ($existing === null || $existing->getId() === $excludeId) {
            return null;
        }
        return $existing->getUri() === $uri ? $existing : null;
    }

    private function optionalSecret(array $body): ?string
    {
        if (!array_key_exists('client_secret', $body) || $body['client_secret'] === null) {
            return null;
        }
        return $this->hashSecret($body['client_secret']);
    }

    private function hashSecret(mixed $secret): string
    {
        if (!is_string($secret) || trim($secret) === '') {
            throw new ValidationFailed("'client_secret' must be a non-empty string");
        }
        return $this->secretsService->hashPassword($secret);
    }

    private static function toArray(Client $client): array
    {
        return [
            'id' => $client->getId(),
            'name' => $client->getName(),
            'realm_id' => $client->getRealmId(),
            'uri' => $client->getUri(),
            'require_auth' => $client->requiresAuth(),
            'scope' => $client->getScopeString(),
            'has_secret' => $client->getClientSecret() !== null && $client->getClientSecret() !== '',
            'created_at' => formatSqlDatetime($client->getCreatedAt()),
        ];
    }
}
