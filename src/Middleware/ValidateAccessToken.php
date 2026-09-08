<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
use AuthServer\Response\BearerChallenge;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\TokenValidator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class ValidateAccessToken implements MiddlewareInterface
{
    private TokenValidator $tokenValidator;

    public function __construct(
        TokenValidator $tokenValidator
    ) {
        $this->tokenValidator = $tokenValidator;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        $authHeader = $request->getHeaderLine('Authorization');
        $token = '';
        if (str_starts_with($authHeader, 'Bearer ')) {
            $token = substr($authHeader, 7);
        }
        if ($token === '') {
            return $this->unauthorized($realm->getName(), 'missing authorization header');
        }

        try {
            $parsed = $this->tokenValidator->parseValidToken($token, $realm);

            $request = $request->withAttribute('accessTokenParsed', $parsed);
            return $handler->handle($request);
        } catch (ValidationFailed $e) {
            return $this->unauthorized($realm->getName(), $e->getMessage());
        }
    }

    /**
     * RFC 6750 §3: a 401 from the resource server carries a Bearer
     * challenge so Keycloak clients know how to retry.
     *
     * Missing/invalid credentials were previously a 400; the resource
     * server SHOULD return 401 (Keycloak clients rely on it).
     * `error="invalid_token"` is used even for a missing header — RFC 6750
     * §3.1 would prescribe `invalid_request` there, but Keycloak returns
     * `invalid_token`, and this server targets Keycloak parity.
     */
    private function unauthorized(string $realmName, string $description): ResponseInterface
    {
        $response = new Response();
        $response = JsonResponse::error(
            $response,
            'Invalid token',
            $description,
            401
        );

        return $response->withHeader('WWW-Authenticate', BearerChallenge::create($realmName, $description));
    }
}
