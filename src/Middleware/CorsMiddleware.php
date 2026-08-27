<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class CorsMiddleware implements MiddlewareInterface
{
    private const ALLOW_ALL = '*';
    private const ALLOWED_HEADERS = 'content-type,accept,origin,authorization';
    private const ALLOWED_METHODS = 'GET,POST,PUT,DELETE,OPTIONS';

    /**
     * @param list<string> $allowedOrigins explicit origins, or one '*' /
     *                                     empty-list entry meaning reflect-any-origin (dev)
     */
    public function __construct(private readonly array $allowedOrigins = [self::ALLOW_ALL])
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if ($request->getMethod() === 'OPTIONS') {
            $response = new Response();
            return $this->withCorsHeaders($response->withStatus(204), $origin);
        }

        return $this->withCorsHeaders($handler->handle($request), $origin);
    }

    private function withCorsHeaders(ResponseInterface $response, string $origin): ResponseInterface
    {
        $reflectsOrigin = $origin !== '' && $this->isAllowed($origin);

        $response = $response->withHeader(
            'Access-Control-Allow-Origin',
            $reflectsOrigin ? $origin : self::ALLOW_ALL
        );
        if ($reflectsOrigin) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }
        if (!$response->hasHeader('Access-Control-Allow-Headers')) {
            $response = $response->withHeader('Access-Control-Allow-Headers', self::ALLOWED_HEADERS);
        }
        if (!$response->hasHeader('Access-Control-Allow-Methods')) {
            $response = $response->withHeader('Access-Control-Allow-Methods', self::ALLOWED_METHODS);
        }

        return $response;
    }

    private function isAllowed(string $origin): bool
    {
        return $this->allowsAnyOrigin() || in_array($origin, $this->allowedOrigins, true);
    }

    private function allowsAnyOrigin(): bool
    {
        return $this->allowedOrigins === []
            || in_array(self::ALLOW_ALL, $this->allowedOrigins, true);
    }
}
