<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * JSON request helpers for tests that exercise the Admin API. Requires the
 * consuming class to expose `self::$app` (Slim app) and `self::$adminKey`.
 */
trait AdminApiTrait
{
    private function createRequest(
        string $method,
        string $path,
        array $body = [],
        array $query = [],
        ?string $auth = null
    ): ServerRequestInterface {
        $uri = $path;
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);
        if (!empty($body)) {
            $request->getBody()->write(json_encode($body));
            $request->getBody()->rewind();
        }
        $request = $request->withHeader('Content-Type', 'application/json');
        if ($auth !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $auth);
        }
        return $request;
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    private function assertStatus(int $expected, ServerRequestInterface $request): array
    {
        $response = $this->handle($request);
        self::assertSame($expected, $response->getStatusCode());
        $body = (string) $response->getBody();
        return $body === '' ? [] : json_decode($body, true) ?? [];
    }

    private function adminRequest(string $method, string $path, array $body = [], array $query = []): ServerRequestInterface
    {
        return $this->createRequest($method, $path, $body, $query, self::$adminKey);
    }

    /**
     * Asserts the `{items,total,limit,offset}` list envelope and returns items.
     *
     * @return array<int, mixed>
     */
    private function assertEnvelope(array $data, int $limit = 50, int $offset = 0): array
    {
        self::assertArrayHasKey('items', $data);
        self::assertSame(count($data['items']), $data['total']);
        self::assertSame($limit, $data['limit']);
        self::assertSame($offset, $data['offset']);
        return $data['items'];
    }
}
