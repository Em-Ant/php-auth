<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\MigrationFailed;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\MigrationRunner;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class MigrationsController
{
    private MigrationRunner $runner;

    public function __construct(MigrationRunner $runner)
    {
        $this->runner = $runner;
    }

    public function migrate(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $applied = $this->runner->migrate();
        } catch (MigrationFailed $e) {
            return JsonResponse::error($response, 'migration_failed', $e->getMessage(), 500);
        }

        return JsonResponse::create($response, [
            'applied' => array_map(fn($m) => [
                'version' => $m->version,
                'name'    => $m->name,
            ], $applied),
            'count'   => count($applied),
        ]);
    }

    public function rollback(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $steps = max(1, (int) ($params['steps'] ?? 1));

        try {
            $rolled = $this->runner->rollback($steps);
        } catch (MigrationFailed $e) {
            return JsonResponse::error($response, 'rollback_failed', $e->getMessage(), 400);
        }

        return JsonResponse::create($response, [
            'rolled_back' => array_map(fn($m) => [
                'version' => $m->version,
                'name'    => $m->name,
            ], $rolled),
            'count'       => count($rolled),
        ]);
    }

    public function go(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $target = (int) ($params['version'] ?? -1);

        if ($target < 0) {
            return JsonResponse::error(
                $response,
                'invalid_version',
                'query param "version" is required and must be >= 0',
                400
            );
        }

        try {
            $result = $this->runner->go($target);
        } catch (MigrationFailed $e) {
            return JsonResponse::error($response, 'migration_failed', $e->getMessage(), 400);
        }

        return JsonResponse::create($response, [
            'applied'    => array_map(fn($m) => ['version' => $m->version, 'name' => $m->name], $result),
            'count'      => count($result),
            'target'     => $target,
        ]);
    }

    public function status(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $status = $this->runner->status();

        return JsonResponse::create($response, [
            'migrations' => $status,
            'count'      => count($status),
        ]);
    }

    public function dryRun(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $pending = $this->runner->dryRun();

        return JsonResponse::create($response, [
            'pending' => $pending,
            'count'   => count($pending),
        ]);
    }
}
