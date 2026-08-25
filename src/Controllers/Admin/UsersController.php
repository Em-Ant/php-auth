<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\User;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\SecretsService;
use AuthServer\Services\UserAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\format_sql_datetime;
use function AuthServer\sql_now;
use function AuthServer\getGuid;

class UsersController
{
    use ValidatesAdminInput;

    private const DEFAULT_ROLES = 'basic';

    public function __construct(
        private readonly UserRepository $users,
        private readonly RealmRepository $realms,
        private readonly SessionRepository $sessions,
        private readonly OfflineSessionRepository $offlineSessions,
        private readonly SecretsService $secretsService,
        private readonly UserAdminService $userAdmin,
        private readonly RoleRepository $roles,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $realmId = isset($query['realm_id']) && $query['realm_id'] !== ''
            ? $query['realm_id']
            : null;

        return JsonResponse::create($response, [
            'users' => array_map(
                fn(User $user) => self::toArray($user),
                $this->users->findAll($realmId)
            ),
        ]);
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);

            $realmId = $this->requiredString($body, 'realm_id');
            $email = $this->requiredString($body, 'email');
            $password = $this->requiredString($body, 'password');

            if ($this->realms->findById($realmId) === null) {
                throw new ValidationFailed("unknown realm '$realmId'");
            }

            if ($this->users->findByEmailAndRealmId($email, $realmId) !== null) {
                throw new ConflictException("user '$email' already exists in this realm");
            }

            $realmRoles = self::splitRoles($this->optionalString($body, 'realm_roles', null) ?? self::DEFAULT_ROLES);

            $user = new User(
                getGuid(),
                $realmId,
                $this->optionalString($body, 'name', null) ?? '',
                $email,
                $this->secretsService->hashPassword($password),
                sql_now(),
                $this->optionalBool($body, 'valid', true)
            );

            $created = $this->userAdmin->createUser($user, $realmRoles);

            return JsonResponse::create($response, self::toArray($created), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $this->findUserOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, self::toArray($user));
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $existing = $this->findUserOrFail($request, $request->getAttribute('id'));

            $body = (array) ($request->getParsedBody() ?? []);

            $realmId = $this->optionalString($body, 'realm_id', null) ?? $existing->getRealmId();
            if ($this->realms->findById($realmId) === null) {
                throw new ValidationFailed("unknown realm '$realmId'");
            }

            $email = $this->optionalString($body, 'email', null) ?? $existing->getEmail();
            $duplicate = $this->users->findByEmailAndRealmId($email, $realmId);
            if ($duplicate !== null && $duplicate->getId() !== $existing->getId()) {
                throw new ConflictException("user '$email' already exists in this realm");
            }

            $realmRoles = $this->updatedRealmRoles($body, $existing);

            $user = new User(
                $existing->getId(),
                $realmId,
                $this->optionalString($body, 'name', null) ?? $existing->getName(),
                $email,
                $this->updatedPassword($body, $existing),
                format_sql_datetime($existing->getCreatedAt()),
                $this->optionalBool($body, 'valid', $existing->getValid())
            );

            $this->userAdmin->updateUser($user, $realmRoles);

            return JsonResponse::create($response, self::toArray($user));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findUserOrFail($request, $id);

        if ($this->sessions->countActiveByUserId($id) > 0) {
            throw new ConflictException("user '$id' still has active sessions");
        }

        if ($this->offlineSessions->countActiveByUserId($id) > 0) {
            throw new ConflictException("user '$id' still has active offline sessions");
        }

        // Remove the (already expired) offline grants so the FK does not block
        // the delete and no orphan rows survive the user.
        $this->offlineSessions->deleteByUserId($id);
        $this->users->delete($id);

        return $response->withStatus(204);
    }

    private function findUserOrFail(ServerRequestInterface $request, string $id): User
    {
        $user = $this->users->findById($id);
        if ($user === null) {
            throw new HttpNotFoundException($request, "user '$id' not found");
        }
        return $user;
    }

    private function updatedRealmRoles(array $body, User $existing): array
    {
        $raw = $this->optionalString($body, 'realm_roles', null);
        if ($raw === null) {
            return $this->roles->findRealmRoleNamesByUserId(
                $existing->getId(),
                $existing->getRealmId()
            );
        }
        return self::splitRoles($raw);
    }

    private static function splitRoles(string $roles): array
    {
        $parts = explode(' ', trim($roles));
        return array_values(array_filter($parts, fn(string $p) => $p !== ''));
    }

    private function updatedPassword(array $body, User $existing): string
    {
        if (!array_key_exists('password', $body) || $body['password'] === null) {
            return $existing->getPassword();
        }
        if (!is_string($body['password']) || trim($body['password']) === '') {
            throw new ValidationFailed("'password' must be a non-empty string");
        }
        return $this->secretsService->hashPassword($body['password']);
    }

    private static function toArray(User $user): array
    {
        return [
            'id' => $user->getId(),
            'realm_id' => $user->getRealmId(),
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'valid' => $user->getValid(),
            'created_at' => format_sql_datetime($user->getCreatedAt()),
        ];
    }
}
