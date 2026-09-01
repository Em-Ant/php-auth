<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Role;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\RoleAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class RolesController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly RoleRepository $roles,
        private readonly RoleAdminService $roleAdmin,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->roles->searchAll(
            $this->queryString($query, 'realm_id'),
            $this->queryString($query, 'client_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(fn(Role $role) => self::toArray($role), $result['items']),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);

            $role = $this->roleAdmin->create(
                $this->requiredString($body, 'realm_id'),
                $this->optionalString($body, 'client_id', null),
                [
                    'name' => $this->requiredString($body, 'name'),
                    'description' => $this->optionalString($body, 'description', null),
                ],
                $request
            );

            return JsonResponse::create($response, self::toArray($role), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $role = $this->findRoleOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, self::toArray($role));
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $existing = $this->findRoleOrFail($request, $request->getAttribute('id'));

            $body = (array) ($request->getParsedBody() ?? []);

            $role = $this->roleAdmin->update($existing, [
                'name' => $this->optionalString($body, 'name', null) ?? $existing->getName(),
                'description' => $this->optionalString($body, 'description', $existing->getDescription()),
            ], $request);

            return JsonResponse::create($response, self::toArray($role));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findRoleOrFail($request, $id);

        $this->roleAdmin->deleteRole($id, $request);

        return $response->withStatus(204);
    }

    private function findRoleOrFail(ServerRequestInterface $request, string $id): Role
    {
        $role = $this->roles->findById($id);
        if ($role === null) {
            throw new HttpNotFoundException($request, "role '$id' not found");
        }
        return $role;
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
