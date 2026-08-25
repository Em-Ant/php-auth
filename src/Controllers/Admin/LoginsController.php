<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Interfaces\LoginRepository;
use AuthServer\Models\Login;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\format_sql_datetime;

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
        $realmId = isset($query['realm_id']) && $query['realm_id'] !== '' ? $query['realm_id'] : null;
        $clientId = isset($query['client_id']) && $query['client_id'] !== '' ? $query['client_id'] : null;

        return JsonResponse::create($response, [
            'logins' => array_map(
                fn(Login $login) => self::toArray($login),
                $this->logins->findAll($realmId, $clientId)
            ),
        ]);
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
            'created_at' => format_sql_datetime($login->getCreatedAt()),
            'authenticated_at' => format_sql_datetime($login->getAuthenticatedAt()),
            'updated_at' => format_sql_datetime($login->getUpdatedAt()),
        ];
    }
}
