<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
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
        if ($authHeader === '' || !str_starts_with($authHeader, 'Bearer ')) {
            $response = new Response();
            return JsonResponse::error(
                $response,
                'Invalid token',
                'missing authorization header',
                400
            );
        }

        $token = substr($authHeader, 7);

        try {
            $parsed = $this->tokenValidator->parseValidToken($token, $realm);

            $request = $request->withAttribute('accessTokenParsed', $parsed);
            return $handler->handle($request);
        } catch (ValidationFailed $e) {
            $response = new Response();
            return JsonResponse::error(
                $response,
                'Invalid token',
                $e->getMessage(),
                401
            );
        }
    }
}
