<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\Role;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class UserRolesController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly UserRepository $users,
        private readonly RoleRepository $roles,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $userId = $request->getAttribute('id');
        $this->findUserOrFail($request, $userId);

        $roles = $this->roles->findByUserId($userId);

        return JsonResponse::create(
            $response,
            array_map(fn(Role $role) => self::toArray($role), $roles)
        );
    }

    public function assign(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $userId = $request->getAttribute('id');
            $this->findUserOrFail($request, $userId);

            $body = (array) ($request->getParsedBody() ?? []);
            $roleId = $this->requiredString($body, 'role_id');

            $role = $this->roles->findById($roleId);
            if ($role === null) {
                throw new ValidationFailed("unknown role '$roleId'");
            }

            $this->roles->assignRoleToUser($userId, $roleId);

            return JsonResponse::create($response, self::toArray($role), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function remove(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $userId = $request->getAttribute('id');
        $this->findUserOrFail($request, $userId);

        $roleId = $request->getAttribute('role_id');
        if ($this->roles->findById($roleId) === null) {
            throw new HttpNotFoundException($request, "role '$roleId' not found");
        }

        $this->roles->removeRoleFromUser($userId, $roleId);

        return $response->withStatus(204);
    }

    private function findUserOrFail(ServerRequestInterface $request, string $id): void
    {
        $user = $this->users->findById($id);
        if ($user === null) {
            throw new HttpNotFoundException($request, "user '$id' not found");
        }
    }

    private static function toArray(Role $role): array
    {
        return [
            'id' => $role->getId(),
            'realm_id' => $role->getRealmId(),
            'client_id' => $role->getClientId(),
            'name' => $role->getName(),
            'description' => $role->getDescription(),
            'created_at' => formatSqlDatetime($role->getCreatedAt()),
        ];
    }
}
