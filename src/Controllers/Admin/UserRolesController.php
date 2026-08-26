<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\Role;
use AuthServer\Models\User;
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

        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $roles = $this->roles->findByUserId($userId);
        $total = count($roles);

        // Child collection of a bounded aggregate (one user's assignments),
        // so paging is applied in PHP over the single fetch instead of a
        // dedicated SQL page query.
        $items = array_slice(
            array_map(fn(Role $role) => self::toArray($role), $roles),
            $pagination['offset'],
            $pagination['limit']
        );

        return JsonResponse::paginated(
            $response,
            $items,
            $total,
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function assign(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $userId = $request->getAttribute('id');
            $user = $this->findUserOrFail($request, $userId);

            $body = (array) ($request->getParsedBody() ?? []);
            $roleId = $this->requiredString($body, 'role_id');

            $role = $this->roles->findById($roleId);
            // Same error for unknown and out-of-realm roles so the endpoint
            // does not leak other realms' role ids (realms are hard tenants).
            if ($role === null || $role->getRealmId() !== $user->getRealmId()) {
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
        $this->roles->removeRoleFromUser($userId, $roleId);

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
