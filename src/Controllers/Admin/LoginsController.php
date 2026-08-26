<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Interfaces\LoginRepository;
use AuthServer\Models\Login;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class LoginsController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly LoginRepository $logins,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->logins->searchAll(
            $this->queryString($query, 'realm_id'),
            $this->queryString($query, 'client_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(fn(Login $login) => self::toArray($login), $result['items']),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $login = $this->logins->findById($id);
        if ($login === null) {
            throw new HttpNotFoundException($request, "login '$id' not found");
        }

        $this->logins->delete($id);

        return $response->withStatus(204);
    }

    private static function toArray(Login $login): array
    {
        return [
            'id' => $login->getId(),
            'client_id' => $login->getClientId(),
            'session_id' => $login->getSessionId(),
            'scope' => $login->getScope(),
            'status' => $login->getStatus()->value,
            'created_at' => formatSqlDatetime($login->getCreatedAt()),
            'authenticated_at' => formatSqlDatetime($login->getAuthenticatedAt()),
            'updated_at' => formatSqlDatetime($login->getUpdatedAt()),
        ];
    }
}
