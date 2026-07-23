<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class RevokeController
{
    private AuthenticationOrchestrator $auth_service;

    public function __construct(
        AuthenticationOrchestrator $service,
    ) {
        $this->auth_service = $service;
    }

    public function revoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
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

        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        $this->auth_service->revoke($body, $realm);

        return JsonResponse::create($response, [], 200);
    }
}
