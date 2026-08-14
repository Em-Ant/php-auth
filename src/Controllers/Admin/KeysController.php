<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Response\JsonResponse;
use AuthServer\Services\TokenService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class KeysController
{
    public function __construct(
        private readonly string $keysRoot,
    ) {
    }

    public function generate(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $kid = TokenService::createKeys(keysRoot: $this->keysRoot);

        return JsonResponse::create($response, ['kid' => $kid], 201);
    }
}
