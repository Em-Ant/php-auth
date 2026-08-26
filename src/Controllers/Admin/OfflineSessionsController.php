<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Models\OfflineSession;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

class OfflineSessionsController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly OfflineSessionRepository $offlineSessions
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->offlineSessions->searchAll(
            $this->queryString($query, 'realm_id'),
            $this->queryString($query, 'user_id'),
            $this->queryString($query, 'client_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(
                fn(OfflineSession $s) => $s->jsonSerialize(),
                $result['items']
            ),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $session = $this->requireSession($request);

        return JsonResponse::create($response, $session->jsonSerialize());
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $session = $this->requireSession($request);
        $this->offlineSessions->setExpired($session->getId());

        return $response->withStatus(204);
    }

    private function requireSession(ServerRequestInterface $request): OfflineSession
    {
        $id = (string) $request->getAttribute('id');
        $session = $this->offlineSessions->findById($id);

        if ($session === null) {
            throw new HttpNotFoundException($request, "offline session '$id' not found");
        }

        return $session;
    }
}
