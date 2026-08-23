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

    private const DEFAULT_LIMIT = 50;
    private const MAX_LIMIT = 100;

    public function __construct(
        private readonly OfflineSessionRepository $offlineSessions
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();

        $realmId = $this->queryString($query, 'realm_id');
        $userId = $this->queryString($query, 'user_id');
        $clientId = $this->queryString($query, 'client_id');

        $limit = $this->queryInt($query, 'limit', self::DEFAULT_LIMIT, 1, self::MAX_LIMIT);
        $offset = $this->queryInt($query, 'offset', 0, 0, null);

        $result = $this->offlineSessions->searchAll($realmId, $userId, $clientId, $limit, $offset);

        return JsonResponse::create($response, [
            'items' => array_map(
                fn(OfflineSession $s) => $s->jsonSerialize(),
                $result['items']
            ),
            'total' => $result['total'],
            'limit' => $limit,
            'offset' => $offset,
        ]);
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
