<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Middleware\RateLimitingMiddleware;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\Database;
use AuthServer\Services\RateLimiter;
use DI\Bridge\Slim\Bridge;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class RateLimitingTest extends TestCase
{
    private static \Slim\App $app;
    private static string $testIp = '192.168.1.100';

    public static function setUpBeforeClass(): void
    {
        $pdo = self::createPdo();

        $rateLimiter = new RateLimiter($pdo);

        $limits = [
            '/test-rate-limit' => ['max' => 3, 'window' => 60],
            '/other-endpoint' => ['max' => 5, 'window' => 60],
            '/strict' => ['max' => 1, 'window' => 60],
        ];

        $rateLimitMiddleware = new RateLimitingMiddleware(
            $rateLimiter,
            $limits,
            'remote_addr',
            []
        );

        $container = new \DI\Container();

        self::$app = Bridge::create($container);
        self::$app->addErrorMiddleware(true, true, true);

        self::$app->get('/test-rate-limit', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        })->add($rateLimitMiddleware);

        self::$app->get('/other-endpoint', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        })->add($rateLimitMiddleware);

        self::$app->get('/strict', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        })->add($rateLimitMiddleware);

        self::$app->get('/unprotected', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        });
    }

    private static function createPdo(): \PDO
    {
        $pdo = Database::connect('sqlite::memory:');
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip          TEXT NOT NULL,
                endpoint    TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (ip, endpoint, window_start)
            )
        ');
        return $pdo;
    }

    private function createRequest(string $method, string $path, string $ip = ''): ServerRequestInterface
    {
        $serverParams = $ip !== '' ? ['REMOTE_ADDR' => $ip] : [];
        return (new ServerRequestFactory())->createServerRequest($method, $path, $serverParams);
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    public function testUnprotectedEndpointNotRateLimited(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $request = $this->createRequest('GET', '/unprotected', self::$testIp);
            $response = $this->handle($request);
            self::assertSame(200, $response->getStatusCode(), "Failed at request {$i}");
        }
    }

    public function testAllowsRequestsUnderLimit(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/test-rate-limit', self::$testIp);
            $response = $this->handle($request);
            self::assertSame(200, $response->getStatusCode(), "Request {$i} should be allowed");
        }
    }

    public function testBlocksRequestOverLimit(): void
    {
        // 3 allowed, 4th should be blocked
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/strict', self::$testIp);
            $this->handle($request);
        }

        $request = $this->createRequest('GET', '/strict', self::$testIp);
        $response = $this->handle($request);

        self::assertSame(429, $response->getStatusCode());
    }

    public function testRateLimitHeadersOnSuccess(): void
    {
        $request = $this->createRequest('GET', '/test-rate-limit', '10.0.0.1');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('3', $response->getHeaderLine('X-RateLimit-Limit'));
        self::assertSame('2', $response->getHeaderLine('X-RateLimit-Remaining'));
    }

    public function testRateLimitHeadersOnBlock(): void
    {
        $ip = '10.0.0.2';
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/test-rate-limit', $ip);
            $this->handle($request);
        }

        $request = $this->createRequest('GET', '/test-rate-limit', $ip);
        $response = $this->handle($request);

        self::assertSame(429, $response->getStatusCode());
        self::assertSame('3', $response->getHeaderLine('X-RateLimit-Limit'));
        self::assertSame('0', $response->getHeaderLine('X-RateLimit-Remaining'));
        self::assertNotEmpty($response->getHeaderLine('Retry-After'));

        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertSame('rate_limit_exceeded', $body['error']);
    }

    public function testDifferentEndpointsHaveSeparateCounters(): void
    {
        $ip = '10.0.0.3';

        // Exhaust /test-rate-limit
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/test-rate-limit', $ip);
            $this->handle($request);
        }

        // /other-endpoint should still be fresh
        $request = $this->createRequest('GET', '/other-endpoint', $ip);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('5', $response->getHeaderLine('X-RateLimit-Limit'));
    }

    public function testDifferentIpsHaveSeparateCounters(): void
    {
        $ipA = '10.0.0.10';
        $ipB = '10.0.0.11';

        // Exhaust for ipA
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/test-rate-limit', $ipA);
            $this->handle($request);
        }

        // ipB should still be allowed
        $request = $this->createRequest('GET', '/test-rate-limit', $ipB);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testXForwardedForIpSource(): void
    {
        $pdo = self::createPdo();

        $rateLimiter = new RateLimiter($pdo);

        $limits = ['/xff-test' => ['max' => 2, 'window' => 60]];

        $middleware = new RateLimitingMiddleware(
            $rateLimiter,
            $limits,
            'x_forwarded_for',
            ['10.0.0.1']  // trusted proxy
        );

        $container = new \DI\Container();
        $app = Bridge::create($container);
        $app->addErrorMiddleware(true, true, true);

        $app->get('/xff-test', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        })->add($middleware);

        $mkReq = function () {
            $r = (new ServerRequestFactory())->createServerRequest('GET', '/xff-test', ['REMOTE_ADDR' => '10.0.0.1']);
            return $r->withHeader('X-Forwarded-For', '203.0.113.50');
        };

        $response = $app->handle($mkReq());
        self::assertSame(200, $response->getStatusCode());

        $response2 = $app->handle($mkReq());
        self::assertSame(200, $response2->getStatusCode());

        $response3 = $app->handle($mkReq());
        self::assertSame(429, $response3->getStatusCode());
    }

    public function testUntrustedProxyFallsBackToRemoteAddr(): void
    {
        $pdo = self::createPdo();

        $rateLimiter = new RateLimiter($pdo);

        $limits = ['/xff-fallback' => ['max' => 1, 'window' => 60]];

        // Empty trusted proxies → x_forwarded_for not trusted
        $middleware = new RateLimitingMiddleware(
            $rateLimiter,
            $limits,
            'x_forwarded_for',
            []  // no trusted proxies
        );

        $container = new \DI\Container();
        $app = Bridge::create($container);
        $app->addErrorMiddleware(true, true, true);

        $app->get('/xff-fallback', function (ServerRequestInterface $request, ResponseInterface $response) {
            return JsonResponse::create($response, ['status' => 'ok']);
        })->add($middleware);

        // REMOTE_ADDR is the proxy IP, X-Forwarded-For has the client IP
        // But proxy is not trusted → rate limiter uses REMOTE_ADDR
        $mkReq = function () {
            $r = (new ServerRequestFactory())->createServerRequest('GET', '/xff-fallback', ['REMOTE_ADDR' => '10.0.0.1']);
            return $r->withHeader('X-Forwarded-For', '203.0.113.50');
        };

        $response = $app->handle($mkReq());
        self::assertSame(200, $response->getStatusCode());

        // Second request from REMOTE_ADDR → should be blocked
        $response2 = $app->handle($mkReq());
        self::assertSame(429, $response2->getStatusCode());
    }

    public function testUnconfiguredEndpointNotRateLimited(): void
    {
        $request = $this->createRequest('GET', '/test-rate-limit', self::$testIp);
        for ($i = 0; $i < 3; $i++) {
            $this->handle($request);
        }

        // Different path not in limits config
        // Actually our test app only has the routes we defined
        // /unprotected has no middleware at all
        $request = $this->createRequest('GET', '/unprotected', self::$testIp);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testMissingRemoteAddrReturns400(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/test-rate-limit');
        // No server params at all

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }
}
