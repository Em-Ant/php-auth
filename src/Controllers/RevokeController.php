<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\ClientCredentials;
use AuthServer\Services\TokenRevocationService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class RevokeController
{
    private TokenRevocationService $revocationService;

    public function __construct(
        TokenRevocationService $revocationService,
    ) {
        $this->revocationService = $revocationService;
    }

    public function revoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $body = ClientCredentials::mergeFromBasicHeader(
            $request->getParsedBody() ?? [],
            $request->getHeaderLine('Authorization')
        );

        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        try {
            $this->revocationService->revoke($body, $realm);
        } catch (AuthenticationFailed $e) {
            return JsonResponse::error(
                $response,
                'invalid_client',
                $e->getMessage(),
                401
            );
        }

        return JsonResponse::create($response, [], 200);
    }
}
