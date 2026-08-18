<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\get_guid;

class RealmsController
{
    use ValidatesAdminInput;

    private const DEFAULT_TTL = 1800;
    private const DEFAULT_ACCESS_TTL = 300;
    private const DEFAULT_SESSION_TTL = 86400;
    private const DEFAULT_SCOPE = 'openid profile email';

    public function __construct(
        private readonly RealmRepository $realms,
        private readonly ClientRepository $clients,
        private readonly UserRepository $users,
        private readonly KeyStore $keyStore,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        return JsonResponse::create($response, [
            'realms' => array_map(
                fn(Realm $realm) => self::toArray($realm),
                $this->realms->findAll()
            ),
        ]);
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);

            $name = $this->requiredString($body, 'name');
            $keysId = $this->requiredString($body, 'keys_id');

            if ($this->realms->findByName($name) !== null) {
                throw new ConflictException("realm '$name' already exists");
            }

            $this->assertKeysExist($keysId);

            $realm = new Realm(
                get_guid(),
                $name,
                $keysId,
                $this->optionalInt($body, 'refresh_token_expires_in', self::DEFAULT_TTL),
                $this->optionalInt($body, 'access_token_expires_in', self::DEFAULT_ACCESS_TTL),
                $this->optionalInt($body, 'pending_login_expires_in', self::DEFAULT_TTL),
                $this->optionalInt($body, 'authenticated_login_expires_in', self::DEFAULT_TTL),
                $this->optionalInt($body, 'session_expires_in', self::DEFAULT_SESSION_TTL),
                $this->optionalInt($body, 'idle_session_expires_in', self::DEFAULT_TTL),
                $this->optionalString($body, 'scope', null) ?? self::DEFAULT_SCOPE,
                gmdate('Y-m-d H:i:s')
            );

            $this->realms->create($realm);

            return JsonResponse::create($response, self::toArray($realm), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $realm = $this->findRealmOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, self::toArray($realm));
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $existing = $this->findRealmOrFail($request, $request->getAttribute('id'));

            $body = (array) ($request->getParsedBody() ?? []);

            $name = $this->optionalString($body, 'name', null) ?? $existing->getName();
            if ($this->realms->findByName($name) !== null && $name !== $existing->getName()) {
                throw new ConflictException("realm '$name' already exists");
            }

            $keysId = $this->optionalString($body, 'keys_id', null) ?? $existing->getKeysId();
            $this->assertKeysExist($keysId);

            $realm = new Realm(
                $existing->getId(),
                $name,
                $keysId,
                $this->optionalInt($body, 'refresh_token_expires_in', $existing->getRefreshTokenExpiresIn()),
                $this->optionalInt($body, 'access_token_expires_in', $existing->getAccessTokenExpiresIn()),
                $this->optionalInt($body, 'pending_login_expires_in', $existing->getPendingLoginExpiresIn()),
                $this->optionalInt(
                    $body,
                    'authenticated_login_expires_in',
                    $existing->getAuthenticatedLoginExpiresIn()
                ),
                $this->optionalInt($body, 'session_expires_in', $existing->getSessionExpiresIn()),
                $this->optionalInt($body, 'idle_session_expires_in', $existing->getIdleSessionExpiresIn()),
                $this->optionalString($body, 'scope', null) ?? implode(' ', $existing->getScope()),
                $existing->getCreatedAt()->format('Y-m-d H:i:s')
            );

            $this->realms->update($realm);

            return JsonResponse::create($response, self::toArray($realm));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $realm = $this->findRealmOrFail($request, $id);

        if ($this->clients->countByRealmId($id) > 0 || $this->users->countByRealmId($id) > 0) {
            throw new ConflictException("realm '$id' still has clients or users");
        }

        $this->realms->delete($id);

        return $response->withStatus(204);
    }

    private function findRealmOrFail(ServerRequestInterface $request, string $id): Realm
    {
        $realm = $this->realms->findById($id);
        if ($realm === null) {
            throw new HttpNotFoundException($request, "realm '$id' not found");
        }
        return $realm;
    }

    private function assertKeysExist(string $keysId): void
    {
        try {
            $this->keyStore->findKeys($keysId);
        } catch (\RuntimeException $e) {
            throw new ValidationFailed("unknown keys_id '$keysId'");
        }
    }

    private static function toArray(Realm $realm): array
    {
        return [
            'id' => $realm->getId(),
            'name' => $realm->getName(),
            'keys_id' => $realm->getKeysId(),
            'refresh_token_expires_in' => $realm->getRefreshTokenExpiresIn(),
            'access_token_expires_in' => $realm->getAccessTokenExpiresIn(),
            'pending_login_expires_in' => $realm->getPendingLoginExpiresIn(),
            'authenticated_login_expires_in' => $realm->getAuthenticatedLoginExpiresIn(),
            'session_expires_in' => $realm->getSessionExpiresIn(),
            'idle_session_expires_in' => $realm->getIdleSessionExpiresIn(),
            'scope' => implode(' ', $realm->getScope()),
            'created_at' => $realm->getCreatedAt()->format('Y-m-d H:i:s'),
        ];
    }
}
