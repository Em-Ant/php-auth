<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Models\Client;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\ClientAdminService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use function AuthServer\formatSqlDatetime;

class ClientsController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly ClientAdminService $clientAdmin,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $pagination = $this->paginationFromQuery($query);

        $result = $this->clients->searchAll(
            $this->queryString($query, 'realm_id'),
            $pagination['limit'],
            $pagination['offset']
        );

        return JsonResponse::paginated(
            $response,
            array_map(fn(Client $client) => self::toArray($client), $result['items']),
            $result['total'],
            $pagination['limit'],
            $pagination['offset']
        );
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);

            $client = $this->clientAdmin->create([
                'name' => $this->requiredString($body, 'name'),
                'uri' => $this->requiredString($body, 'uri'),
                'require_auth' => $this->strictBool($body, 'require_auth', false),
                'client_secret' => $body['client_secret'] ?? null,
                'scope' => $this->optionalString($body, 'scope', null),
            ], $this->requiredString($body, 'realm_id'));

            return JsonResponse::create($response, self::toArray($client), 201);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $client = $this->findClientOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, self::toArray($client));
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $existing = $this->findClientOrFail($request, $request->getAttribute('id'));

            $body = (array) ($request->getParsedBody() ?? []);

            $client = $this->clientAdmin->update($existing, [
                'name' => $this->optionalString($body, 'name', null) ?? $existing->getName(),
                'uri' => $this->optionalString($body, 'uri', null) ?? $existing->getUri(),
                'realm_id' => $this->optionalString($body, 'realm_id', null) ?? $existing->getRealmId(),
                'require_auth' => $this->strictBool($body, 'require_auth', $existing->requiresAuth()),
                'client_secret' => $body['client_secret'] ?? null,
                'scope' => $this->optionalString($body, 'scope', $existing->getScopeString()),
            ]);

            return JsonResponse::create($response, self::toArray($client));
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $id = $request->getAttribute('id');
        $this->findClientOrFail($request, $id);

        $this->clientAdmin->delete($id);

        return $response->withStatus(204);
    }

    private function findClientOrFail(ServerRequestInterface $request, string $id): Client
    {
        $client = $this->clients->findById($id);
        if ($client === null) {
            throw new HttpNotFoundException($request, "client '$id' not found");
        }
        return $client;
    }

    private static function toArray(Client $client): array
    {
        return [
            'id' => $client->getId(),
            'name' => $client->getName(),
            'realm_id' => $client->getRealmId(),
            'uri' => $client->getUri(),
            'require_auth' => $client->requiresAuth(),
            'scope' => $client->getScopeString(),
            'has_secret' => $client->hasSecret(),
            'created_at' => formatSqlDatetime($client->getCreatedAt()),
        ];
    }
}
