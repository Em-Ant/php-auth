<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\ScopeRoleMapping;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\ScopeRoleAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

class ScopeRolesController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly RoleRepository $roles,
        private readonly ScopeRoleAdminService $scopeRoleAdmin,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $clientId = $request->getAttribute('id');
        $this->findClientOrFail($request, $clientId);

        $grouped = $this->roles->findScopeRoleMappings($clientId);

        $mappings = [];
        foreach ($grouped as $scope => $scopeMappings) {
            foreach ($scopeMappings as $mapping) {
                $mappings[] = self::mappingToArray($mapping->roleId, $scope, $mapping->roleName, $mapping->required);
            }
        }

        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);
        $total = count($mappings);

        // Child collection of a bounded aggregate (one client's mappings),
        // so paging is applied in PHP over the single fetch instead of a
        // dedicated SQL page query.
        $items = array_slice($mappings, $pagination['offset'], $pagination['limit']);

        return JsonResponse::paginated(
            $response,
            $items,
            $total,
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $clientId = $request->getAttribute('id');
            $this->findClientOrFail($request, $clientId);

            $body = (array) ($request->getParsedBody() ?? []);
            $scope = $this->requiredString($body, 'scope');
            $roleId = $this->requiredString($body, 'role_id');
            $required = $this->strictBool($body, 'required', false);

            $mapping = $this->scopeRoleAdmin->create($clientId, $scope, $roleId, $required, $request);

            $data = self::mappingToArray($mapping->roleId, $mapping->scope, $mapping->roleName, $mapping->required);

            return JsonResponse::create($response, $data, 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $clientId = $request->getAttribute('id');
            $this->findClientOrFail($request, $clientId);

            $scope = $request->getAttribute('scope');
            $roleId = $request->getAttribute('role_id');

            $existing = $this->roles->findScopeRoleMapping($clientId, $scope, $roleId);
            if ($existing === null) {
                throw new HttpNotFoundException($request, "mapping for scope '$scope' and role '$roleId' not found");
            }

            $body = (array) ($request->getParsedBody() ?? []);
            $required = $this->strictBool($body, 'required', $existing->required);

            $this->scopeRoleAdmin->update($clientId, $scope, $roleId, $required, $request);

            return JsonResponse::create($response, [
                'scope' => $scope,
                'role_id' => $roleId,
                'required' => $required,
            ]);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $clientId = $request->getAttribute('id');
        $this->findClientOrFail($request, $clientId);

        $scope = $request->getAttribute('scope');
        $roleId = $request->getAttribute('role_id');

        $this->scopeRoleAdmin->delete($clientId, $scope, $roleId, $request);

        return $response->withStatus(204);
    }

    private function findClientOrFail(ServerRequestInterface $request, string $id): void
    {
        $client = $this->clients->findById($id);
        if ($client === null) {
            throw new HttpNotFoundException($request, "client '$id' not found");
        }
    }

    private static function mappingToArray(string $roleId, string $scope, string $roleName, bool $required): array
    {
        return [
            'scope' => $scope,
            'role_id' => $roleId,
            'role_name' => $roleName,
            'required' => $required,
        ];
    }
}
