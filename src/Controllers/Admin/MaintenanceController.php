<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Response\JsonResponse;
use AuthServer\Services\MaintenanceService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class MaintenanceController
{
    public function __construct(
        private readonly MaintenanceService $maintenance,
    ) {
    }

    public function cleanup(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $result = $this->maintenance->cleanup();

        return JsonResponse::create($response, $result);
    }
}
