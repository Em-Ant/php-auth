<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Response\JsonResponse;
use AuthServer\Services\RateLimiter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class RateLimitingMiddleware implements MiddlewareInterface
{
    private RateLimiter $limiter;
    private string $ipSource;
    private array $limits;
    private array $trustedProxies;

    /**
     * @param array<string, array{max: int, window: int}> $limits  endpoint path => config
     * @param string                                       $ipSource  'remote_addr' | 'x_forwarded_for'
     * @param string[] $trustedProxies  IPs/CIDRs allowed to set X-Forwarded-For
     */
    public function __construct(
        RateLimiter $limiter,
        array $limits,
        string $ipSource = 'remote_addr',
        array $trustedProxies = []
    ) {
        $this->limiter = $limiter;
        $this->limits = $limits;
        $this->ipSource = $ipSource;
        $this->trustedProxies = $trustedProxies;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $endpoint = $this->matchEndpoint($path);

        if ($endpoint === null) {
            return $handler->handle($request);
        }

        $ip = $this->resolveIp($request);
        if ($ip === null) {
            $response = new Response();
            return JsonResponse::error(
                $response,
                'bad_request',
                'could not determine client IP',
                400
            );
        }

        $max = $this->limits[$endpoint]['max'];
        $window = $this->limits[$endpoint]['window'];

        if (!$this->limiter->isAllowed($ip, $endpoint, $max, $window)) {
            $retryAfter = $this->limiter->getRetryAfter($ip, $endpoint, $window);
            $response = new Response();
            $body = json_encode([
                'error' => 'rate_limit_exceeded',
                'error_description' => 'too many requests, retry later',
            ], JSON_UNESCAPED_SLASHES);
            $response->getBody()->write($body !== false ? $body : '');
            return $response
                ->withStatus(429)
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Retry-After', (string) $retryAfter)
                ->withHeader('X-RateLimit-Limit', (string) $max)
                ->withHeader('X-RateLimit-Remaining', '0')
                ->withHeader('X-RateLimit-Reset', (string) (time() + $retryAfter));
        }

        $remaining = $this->limiter->getRemaining($ip, $endpoint, $max, $window);
        $response = $handler->handle($request);

        return $response
            ->withHeader('X-RateLimit-Limit', (string) $max)
            ->withHeader('X-RateLimit-Remaining', (string) $remaining);
    }

    private function resolveIp(ServerRequestInterface $request): ?string
    {
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        if ($remoteAddr === null || !filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
            return null;
        }

        if ($this->ipSource === 'remote_addr') {
            return $remoteAddr;
        }

        if ($this->ipSource === 'x_forwarded_for') {
            if (!$this->isTrustedProxy($remoteAddr)) {
                return $remoteAddr;
            }

            $xff = $request->getHeaderLine('X-Forwarded-For');
            if ($xff === '') {
                return $remoteAddr;
            }

            $chain = array_map('trim', explode(',', $xff));
            for ($i = count($chain) - 1; $i >= 0; $i--) {
                $candidate = $chain[$i];
                if (filter_var($candidate, FILTER_VALIDATE_IP) && !$this->isTrustedProxy($candidate)) {
                    return $candidate;
                }
            }
        }

        return $remoteAddr;
    }

    private function isTrustedProxy(string $ip): bool
    {
        foreach ($this->trustedProxies as $proxy) {
            if (str_contains($proxy, '/')) {
                if ($this->ipInCidr($ip, $proxy)) {
                    return true;
                }
            } elseif ($ip === $proxy) {
                return true;
            }
        }
        return false;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        $subnet = $parts[0];
        $bits = (int) ($parts[1] ?? 32);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - $bits);
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private function matchEndpoint(string $path): ?string
    {
        foreach (array_keys($this->limits) as $endpoint) {
            if (str_ends_with($path, $endpoint)) {
                return $endpoint;
            }
        }
        return null;
    }
}
