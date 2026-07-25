<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\TokenIntrospectionService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IntrospectController
{
    private TokenIntrospectionService $introspectionService;

    public function __construct(
        TokenIntrospectionService $introspectionService,
    ) {
        $this->introspectionService = $introspectionService;
    }

    public function introspect(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        $authHeader = $request->getHeaderLine('Authorization');
        if (str_starts_with($authHeader, 'Basic ')) {
            $cred = explode(':', base64_decode(substr($authHeader, 6)));
            if (!isset($body['client_id'])) {
                $body['client_id'] = $cred[0] ?? null;
            }
            if (!isset($body['client_secret'])) {
                $body['client_secret'] = $cred[1] ?? null;
            }
        }

        try {
            /** @var Realm */
            $realm = $request->getAttribute(Realm::class);

            return JsonResponse::create(
                $response,
                $this->introspectionService->introspect($body, $realm),
                200
            );
        } catch (AuthenticationFailed $e) {
            return JsonResponse::error(
                $response,
                'invalid_client',
                $e->getMessage(),
                401
            );
        } catch (ValidationFailed $e) {
            return JsonResponse::error(
                $response,
                'invalid_request',
                $e->getMessage(),
                400
            );
        }
    }
}
