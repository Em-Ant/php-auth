<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Interfaces\SessionRepository;
use AuthServer\Models\Session;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\SessionRevocationService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

class SessionsController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly SessionRepository $sessions,
        private readonly SessionRevocationService $revocations,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->sessions->searchAll(
            $this->queryString($query, 'realm_id'),
            $this->queryString($query, 'user_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(fn(Session $session) => self::toArray($session), $result['items']),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $session = $this->sessions->findById($id);
        if ($session === null) {
            throw new HttpNotFoundException($request, "session '$id' not found");
        }

        $this->revocations->revokeSession($id);

        return $response->withStatus(204);
    }

    public function invalidate(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);
            $userId = $this->optionalString($body, 'user_id', null);
            $clientId = $this->optionalString($body, 'client_id', null);

            if ($userId === null && $clientId === null) {
                return JsonResponse::error(
                    $response,
                    'invalid_request',
                    'either user_id or client_id is required',
                    400
                );
            }

            $count = $this->revocations->revokeFor($userId, $clientId);

            return JsonResponse::create($response, ['invalidated' => $count]);
        } catch (\AuthServer\Exceptions\ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    private static function toArray(Session $session): array
    {
        return [
            'id' => $session->getId(),
            'realm_id' => $session->getRealmId(),
            'user_id' => $session->getUserId(),
            'acr' => $session->getAcr(),
            'status' => $session->getStatus()->value,
            'created_at' => $session->getCreatedAt()->format('Y-m-d H:i:s'),
            'updated_at' => $session->getUpdatedAt()?->format('Y-m-d H:i:s'),
        ];
    }
}
