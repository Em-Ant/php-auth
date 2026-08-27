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
     * @param list<string> $allowedOrigins explicit origins to reflect with
     *                                     credentials. A list containing '*' (or
     *                                     '*' alone) reflects any origin, so the
     *                                     literal '*' is never sent to the browser
     *                                     (which would be rejected alongside
     *                                     `Access-Control-Allow-Credentials`). An
     *                                     empty list denies cross-origin access:
     *                                     no CORS headers are emitted at all.
     */
    public function __construct(private readonly array $allowedOrigins = [self::ALLOW_ALL])
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if ($request->getMethod() === 'OPTIONS') {
            return $this->withCorsHeaders(new Response(), $origin)->withStatus(204);
        }

        return $this->withCorsHeaders($handler->handle($request), $origin);
    }

    private function withCorsHeaders(ResponseInterface $response, string $origin): ResponseInterface
    {
        if ($origin === '' || !$this->isAllowed($origin)) {
            return $this->stripCorsHeaders($response);
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Access-Control-Allow-Credentials', 'true')
            ->withHeader('Access-Control-Allow-Headers', self::ALLOWED_HEADERS)
            ->withHeader('Access-Control-Allow-Methods', self::ALLOWED_METHODS);
    }

    /**
     * Removes any CORS headers that inner handlers may have set, so that a
     * disallowed origin can never read the response, no matter how the
     * response was built (e.g. a hardcoded '*' JSON response).
     */
    private function stripCorsHeaders(ResponseInterface $response): ResponseInterface
    {
        return $response
            ->withoutHeader('Access-Control-Allow-Origin')
            ->withoutHeader('Access-Control-Allow-Credentials')
            ->withoutHeader('Access-Control-Allow-Headers')
            ->withoutHeader('Access-Control-Allow-Methods');
    }

    private function isAllowed(string $origin): bool
    {
        return in_array(self::ALLOW_ALL, $this->allowedOrigins, true)
            || in_array($origin, $this->allowedOrigins, true);
    }
}
