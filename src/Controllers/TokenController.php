<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\TokenGrantService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenController
{
    private TokenGrantService $tokenGrantService;
    private AuthenticationOrchestrator $auth_service;

    public const INVALID_REQUEST = 'Invalid request';

    public function __construct(
        TokenGrantService $tokenGrantService,
        AuthenticationOrchestrator $auth_service,
    ) {
        $this->tokenGrantService = $tokenGrantService;
        $this->auth_service = $auth_service;
    }

    public function token(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        $authHeader = $request->getHeaderLine('Authorization');
        if (str_starts_with($authHeader, 'Basic ')) {
            $cred = explode(':', base64_decode(substr($authHeader, 6)));
            if (!isset($body['client_id'])) {
                $body['client_id'] = $cred[0];
            }
            if (!isset($body['client_secret'])) {
                $body['client_secret'] = $cred[1] ?? null;
            }
        }

        try {
            /** @var Realm */
            $realm = $request->getAttribute(Realm::class);

            $origin = $request->getHeaderLine('Origin')
                ?: $this->auth_service->getClientUri($body['client_id'] ?? '');

            return JsonResponse::create(
                $response,
                $this->tokenGrantService->getTokens($body, $realm),
                200,
                $origin
            );
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        }
    }
}
