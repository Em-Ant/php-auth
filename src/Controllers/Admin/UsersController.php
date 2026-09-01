<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\User;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\UserAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class UsersController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly UserRepository $users,
        private readonly UserAdminService $userAdmin,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->users->searchAll(
            $this->queryString($query, 'realm_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(fn(User $user) => self::toArray($user), $result['items']),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);
            $this->rejectRemovedRealmRoles($body);

            $user = $this->userAdmin->createUser([
                'realm_id' => $this->requiredString($body, 'realm_id'),
                'email' => $this->requiredString($body, 'email'),
                'password' => $this->requiredString($body, 'password'),
                'name' => $this->optionalString($body, 'name', null),
                'valid' => $this->strictBool($body, 'valid', true),
                'email_verified' => $this->strictBool($body, 'email_verified', true),
            ]);

            return JsonResponse::create($response, self::toArray($user), 201);
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
            $this->rejectRemovedRealmRoles($body);

            $user = $this->userAdmin->updateUser($existing, [
                'realm_id' => $this->optionalString($body, 'realm_id', null),
                'email' => $this->optionalString($body, 'email', null),
                'password' => $body['password'] ?? null,
                'name' => $this->optionalString($body, 'name', null),
                'valid' => $this->optionalBool($body, 'valid'),
                'email_verified' => $this->optionalBool($body, 'email_verified'),
            ]);

            return JsonResponse::create($response, self::toArray($user));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findUserOrFail($request, $id);

        $this->userAdmin->deleteUser($id);

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

    private function optionalBool(array $body, string $field): ?bool
    {
        if (!array_key_exists($field, $body) || $body[$field] === null) {
            return null;
        }
        return $this->strictBool($body, $field, false);
    }

    /**
     * `realm_roles` was removed in F-45: roles are explicit entities created
     * via POST /admin/roles and assigned via POST /admin/users/{id}/roles.
     * Fail loudly instead of silently creating a user with no roles — a
     * consumer still sending the old field gets a 400, never a silent no-op.
     */
    private function rejectRemovedRealmRoles(array $body): void
    {
        if (array_key_exists('realm_roles', $body)) {
            throw new ValidationFailed(
                "'realm_roles' is removed (F-45): create roles via POST /admin/roles "
                . 'and assign them via POST /admin/users/{id}/roles'
            );
        }
    }

    private static function toArray(User $user): array
    {
        return [
            'id' => $user->getId(),
            'realm_id' => $user->getRealmId(),
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'valid' => $user->getValid(),
            'email_verified' => $user->getEmailVerified(),
            'created_at' => formatSqlDatetime($user->getCreatedAt()),
        ];
    }
}
