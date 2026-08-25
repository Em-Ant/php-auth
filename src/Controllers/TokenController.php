<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\ClientCredentials;
use AuthServer\Services\TokenGrantService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenController
{
    private TokenGrantService $tokenGrantService;
    private AuthenticationOrchestrator $auth_service;

    public function __construct(
        TokenGrantService $tokenGrantService,
        AuthenticationOrchestrator $auth_service,
    ) {
        $this->tokenGrantService = $tokenGrantService;
        $this->auth_service = $auth_service;
    }

    public function token(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $body = ClientCredentials::mergeFromBasicHeader(
            $request->getParsedBody() ?? [],
            $request->getHeaderLine('Authorization')
        );

        try {
            /** @var Realm */
            $realm = $request->getAttribute(Realm::class);

            $tokens = $this->tokenGrantService->getTokens($body, $realm);

            $origin = $request->getHeaderLine('Origin')
                ?: $this->auth_service->getClientUri($body['client_id'] ?? '');

            return JsonResponse::create($response, $tokens, 200, $origin);
        } catch (OAuth2Error $e) {
            return JsonResponse::errorFromOAuth2Error($response, $e);
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::invalidRequest($response, $e);
        }
    }
}
