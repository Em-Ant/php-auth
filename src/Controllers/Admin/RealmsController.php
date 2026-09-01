<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\RealmAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class RealmsController
{
    use ValidatesAdminInput;

    private const DEFAULT_TTL = 1800;
    private const DEFAULT_ACCESS_TTL = 300;
    private const DEFAULT_SESSION_TTL = 86400;
    private const DEFAULT_OFFLINE_TTL = 2592000;
    private const DEFAULT_SCOPE = 'openid profile email';

    public function __construct(
        private readonly RealmRepository $realms,
        private readonly RealmAdminService $realmAdmin,
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

            $realm = $this->realmAdmin->create($this->realmParams($body, null), $request);

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

            $realm = $this->realmAdmin->update($existing, $this->realmParams($body, $existing), $request);

            return JsonResponse::create($response, self::toArray($realm));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findRealmOrFail($request, $id);

        $this->realmAdmin->delete($id, $request);

        return $response->withStatus(204);
    }

    /**
     * Resolves the realm fields from the request body. `$existing` provides
     * the defaults for absent fields on update; null means create, so the
     * realm config defaults apply instead.
     *
     * @return array{
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
     * }
     */
    private function realmParams(array $body, ?Realm $existing): array
    {
        $defaults = $existing === null
            ? [
                'refresh_token_expires_in' => self::DEFAULT_TTL,
                'access_token_expires_in' => self::DEFAULT_ACCESS_TTL,
                'pending_login_expires_in' => self::DEFAULT_TTL,
                'authenticated_login_expires_in' => self::DEFAULT_TTL,
                'session_expires_in' => self::DEFAULT_SESSION_TTL,
                'idle_session_expires_in' => self::DEFAULT_TTL,
                'scope' => self::DEFAULT_SCOPE,
                'offline_refresh_token_expires_in' => self::DEFAULT_OFFLINE_TTL,
            ]
            : [
                'refresh_token_expires_in' => $existing->getRefreshTokenExpiresIn(),
                'access_token_expires_in' => $existing->getAccessTokenExpiresIn(),
                'pending_login_expires_in' => $existing->getPendingLoginExpiresIn(),
                'authenticated_login_expires_in' => $existing->getAuthenticatedLoginExpiresIn(),
                'session_expires_in' => $existing->getSessionExpiresIn(),
                'idle_session_expires_in' => $existing->getIdleSessionExpiresIn(),
                'scope' => implode(' ', $existing->getScope()),
                'offline_refresh_token_expires_in' => $existing->getOfflineRefreshTokenExpiresIn(),
            ];

        return [
            // Required on create, optional-with-existing-default on update.
            'name' => $existing === null
                ? $this->requiredString($body, 'name')
                : $this->optionalString($body, 'name', null) ?? $existing->getName(),
            'keys_id' => $existing === null
                ? $this->requiredString($body, 'keys_id')
                : $this->optionalString($body, 'keys_id', null) ?? $existing->getKeysId(),
            'refresh_token_expires_in' => $this->optionalInt(
                $body,
                'refresh_token_expires_in',
                $defaults['refresh_token_expires_in']
            ),
            'access_token_expires_in' => $this->optionalInt(
                $body,
                'access_token_expires_in',
                $defaults['access_token_expires_in']
            ),
            'pending_login_expires_in' => $this->optionalInt(
                $body,
                'pending_login_expires_in',
                $defaults['pending_login_expires_in']
            ),
            'authenticated_login_expires_in' => $this->optionalInt(
                $body,
                'authenticated_login_expires_in',
                $defaults['authenticated_login_expires_in']
            ),
            'session_expires_in' => $this->optionalInt(
                $body,
                'session_expires_in',
                $defaults['session_expires_in']
            ),
            'idle_session_expires_in' => $this->optionalInt(
                $body,
                'idle_session_expires_in',
                $defaults['idle_session_expires_in']
            ),
            'scope' => $this->optionalString($body, 'scope', null) ?? $defaults['scope'],
            'offline_refresh_token_expires_in' => $this->optionalInt(
                $body,
                'offline_refresh_token_expires_in',
                $defaults['offline_refresh_token_expires_in']
            ),
        ];
    }

    private function findRealmOrFail(ServerRequestInterface $request, string $id): Realm
    {
        $realm = $this->realms->findById($id);
        if ($realm === null) {
            throw new HttpNotFoundException($request, "realm '$id' not found");
        }
        return $realm;
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
            'offline_refresh_token_expires_in' => $realm->getOfflineRefreshTokenExpiresIn(),
            'scope' => implode(' ', $realm->getScope()),
            'created_at' => formatSqlDatetime($realm->getCreatedAt()),
        ];
    }
}
