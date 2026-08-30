<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Interfaces\RealmRepository as IRealmRepo;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\TokenValidator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Psr7\Response;

final class AdminAuthMiddleware implements MiddlewareInterface
{
    /**
     * @param list<string> $opsAllowList prefix allow-list for static fallback when allowAll is false.
     *                                   Entries are matched against the full request path, so a
     *                                   non-empty base_path must be part of the entry (Definitions
     *                                   prefixes it from config).
     */
    public function __construct(
        private readonly string $adminApiKey,
        private readonly TokenValidator $tokenValidator,
        private readonly IRealmRepo $realmRepository,
        private readonly LoggerInterface $logger,
        private readonly string $adminRealmName = 'admin',
        private readonly bool $allowAll = true,
        private readonly array $opsAllowList = ['/admin/migrations', '/db/migrations', '/admin/maintenance']
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $bearer = $this->extractBearerToken($request);

        if ($bearer !== null) {
            $claims = $this->validateAdminJwt($bearer);
            if ($claims !== null && $this->hasAdminRole($claims)) {
                $request = $request->withAttribute('admin_claims', $claims);
                if (isset($claims['sub'])) {
                    $request = $request->withAttribute('admin_user', $claims['sub']);
                }

                return $handler->handle($request);
            }
        }

        $staticToken = $this->extractStaticToken($request);
        if ($staticToken !== null && $this->adminApiKey !== '' && hash_equals($this->adminApiKey, $staticToken)) {
            if ($this->allowAll || $this->isOpsPath($request)) {
                return $handler->handle($request);
            }
        }

        $response = new Response();
        return JsonResponse::error($response, 'unauthorized', 'invalid or missing admin token', 401);
    }

    private function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth === '' || !str_starts_with($auth, 'Bearer ')) {
            return null;
        }

        $token = substr($auth, 7);
        return $token === '' ? null : $token;
    }

    private function extractStaticToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && str_starts_with($auth, 'Bearer ')) {
            $token = substr($auth, 7);
            if ($token !== '') {
                return $token;
            }
        }

        $header = $request->getHeaderLine('X-Admin-Key');
        if ($header !== '') {
            return $header;
        }

        return null;
    }

    private function isOpsPath(ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();
        foreach ($this->opsAllowList as $prefix) {
            if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function validateAdminJwt(string $token): ?array
    {
        $realm = null;
        try {
            $realm = $this->realmRepository->findByName($this->adminRealmName);
        } catch (\Throwable $e) {
            $this->logger->error('admin realm lookup failed: ' . $e->getMessage());
        }

        if ($realm === null) {
            return null;
        }

        try {
            return $this->tokenValidator->validate($token, $realm, 'Bearer', null);
        } catch (\Throwable $e) {
            $this->logger->error('admin token validation failed: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function hasAdminRole(array $claims): bool
    {
        $realmAccess = $claims['realm_access'] ?? null;
        if (!is_array($realmAccess)) {
            return false;
        }

        $roles = $realmAccess['roles'] ?? null;
        if (!is_array($roles)) {
            return false;
        }

        return in_array('admin', $roles, true);
    }
}
