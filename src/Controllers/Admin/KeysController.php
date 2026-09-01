<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Response\JsonResponse;
use AuthServer\Services\KeyProvisioning;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class KeysController
{
    public function __construct(
        private readonly KeyProvisioning $keyProvisioning,
    ) {
    }

    public function generate(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $kid = $this->keyProvisioning->createKeys();

        return JsonResponse::create($response, ['kid' => $kid], 201);
    }
}
