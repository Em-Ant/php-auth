<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class AdminMiddleware implements MiddlewareInterface
{
    private string $apiKey;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);

        if ($token === null || !hash_equals($this->apiKey, $token)) {
            $response = new Response();
            return JsonResponse::error(
                $response,
                'unauthorized',
                'invalid or missing admin token',
                401
            );
        }

        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }

        $header = $request->getHeaderLine('X-Admin-Key');
        if ($header !== '') {
            return $header;
        }

        return null;
    }
}
