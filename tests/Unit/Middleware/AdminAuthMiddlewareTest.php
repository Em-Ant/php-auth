<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Interfaces\RealmRepository as IRealmRepo;
use AuthServer\Middleware\AdminAuthMiddleware;
use AuthServer\Models\Realm;
use AuthServer\Services\TokenValidator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\NullLogger;

class AdminAuthMiddlewareTest extends TestCase
{
    private const ADMIN_API_KEY = 'dev-admin-token-change-me';
    private const ISSUER = 'http://localhost:8000';

    private TokenValidator $validator;
    private IRealmRepo $realmRepo;
    private Realm $adminRealm;

    protected function setUp(): void
    {
        $this->validator = $this->createMock(TokenValidator::class);
        $this->realmRepo = $this->createMock(IRealmRepo::class);
        $this->adminRealm = new Realm(
            'adc8cc40-943c-4fa4-97ed-2777baa49db5',
            'admin',
            '787248fe-344f-4db3-a287-daef099867c6',
            1800,
            300,
            300,
            300,
            86400,
            1800,
            'openid profile email offline_access',
            '2025-01-01 00:00:00',
            2592000
        );
        $this->realmRepo->method('findByName')->with('admin')->willReturn($this->adminRealm);
    }

    private function middleware(
        bool $allowAll = true,
        array $allowList = ['/admin/migrations', '/admin/maintenance']
    ): AdminAuthMiddleware {
        return new AdminAuthMiddleware(
            self::ADMIN_API_KEY,
            $this->validator,
            $this->realmRepo,
            new NullLogger(),
            'admin',
            $allowAll,
            $allowList
        );
    }

    private function request(
        string $path,
        string $auth = '',
        string $xAdminKey = ''
    ): ServerRequestInterface {
        $uri = $this->createMock(UriInterface::class);
        $uri->method('getPath')->willReturn($path);

        $req = $this->createMock(ServerRequestInterface::class);
        $req->method('getUri')->willReturn($uri);
        $req->method('getHeaderLine')->willReturnMap([
            ['Authorization', $auth],
            ['X-Admin-Key', $xAdminKey],
        ]);
        // withAttribute chaining for enrichment
        $req->method('withAttribute')->willReturnCallback(
            function (string $name, mixed $value) use ($req) {
                return $req;
            }
        );

        return $req;
    }

    private function handlerExpectingHandle(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $resp = $this->createMock(ResponseInterface::class);
        $resp->method('getStatusCode')->willReturn(200);
        $handler->method('handle')->willReturn($resp);
        $handler->expects(self::once())->method('handle');
        return $handler;
    }

    private function handlerExpectingNoHandle(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');
        return $handler;
    }

    /**
     * Static api_key fallback matrix: the validator never matches a JWT, so access
     * is decided solely by the static token, the request path, and allowAll.
     */
    private function assertStaticFallbackAccess(
        string $path,
        string $auth,
        string $xAdminKey,
        bool $allowAll,
        bool $expectPass
    ): void {
        $this->validator->method('validate')->willReturn(null);
        $mw = $this->middleware(allowAll: $allowAll);
        $req = $this->request($path, $auth, $xAdminKey);
        $resp = $mw->process($req, $expectPass ? $this->handlerExpectingHandle() : $this->handlerExpectingNoHandle());
        self::assertSame($expectPass ? 200 : 401, $resp->getStatusCode());
    }

    public function testJwtValidWithAdminRolePassesThrough(): void
    {
        $this->validator->method('validate')
            ->with('jwt-admin', $this->adminRealm, 'Bearer', null)
            ->willReturn(['sub' => 'u1', 'realm_access' => ['roles' => ['admin']], 'exp' => time() + 300]);

        $mw = $this->middleware();
        $req = $this->request('/admin/realms', 'Bearer jwt-admin');
        $handler = $this->handlerExpectingHandle();

        $resp = $mw->process($req, $handler);
        self::assertSame(200, $resp->getStatusCode() === 0 ? 200 : $resp->getStatusCode());
    }

    public function testJwtMissingAdminRoleReturns401(): void
    {
        $this->validator->method('validate')->willReturn(['sub' => 'u1', 'realm_access' => ['roles' => ['basic']]]);

        $mw = $this->middleware();
        $req = $this->request('/admin/realms', 'Bearer jwt-basic');
        $response = $mw->process($req, $this->handlerExpectingNoHandle());
        self::assertSame(401, $response->getStatusCode());
    }

    public function testJwtWithNoRealmAccessReturns401(): void
    {
        $this->validator->method('validate')->willReturn(['sub' => 'u1']);
        $mw = $this->middleware();
        $req = $this->request('/admin/realms', 'Bearer jwt-no-roles');
        $response = $mw->process($req, $this->handlerExpectingNoHandle());
        self::assertSame(401, $response->getStatusCode());
    }

    public function testJwtExpiredReturns401WhenNoStaticFallback(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', 'Bearer expired-jwt', '', allowAll: false, expectPass: false);
    }

    public function testJwtExpiredFallsBackToStaticOnOpsWhenAllowAllFalse(): void
    {
        $this->assertStaticFallbackAccess('/admin/migrations/migrate', 'Bearer ' . self::ADMIN_API_KEY, '', allowAll: false, expectPass: true);
    }

    public function testJwtExpiredFallsBackFailsOnNonOpsWhenAllowAllFalse(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', 'Bearer ' . self::ADMIN_API_KEY, '', allowAll: false, expectPass: false);
    }

    public function testSsoAndOfflineTokensBothPassWhenTheyCarryAdminRole(): void
    {
        $this->validator->method('validate')->willReturnOnConsecutiveCalls(
            ['sub' => 'u1', 'realm_access' => ['roles' => ['admin']], 'scope' => 'openid profile email'],
            ['sub' => 'u1', 'realm_access' => ['roles' => ['admin']], 'scope' => 'openid profile email offline_access']
        );
        $mw = $this->middleware();
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::exactly(2))->method('handle')->willReturn($this->createMock(ResponseInterface::class));

        $mw->process($this->request('/admin/realms', 'Bearer sso-jwt'), $handler);
        $mw->process($this->request('/admin/realms', 'Bearer offline-jwt'), $handler);
    }

    public function testSsoAndOfflineTokensBothFailWhenMissingAdminRole(): void
    {
        $this->validator->method('validate')->willReturn(['sub' => 'u1', 'realm_access' => ['roles' => []]]);
        $mw = $this->middleware(allowAll: true);
        // No static provided, so both should 401
        $resp1 = $mw->process($this->request('/admin/realms', 'Bearer sso-no-admin'), $this->handlerExpectingNoHandle());
        $resp2 = $mw->process($this->request('/admin/realms', 'Bearer offline-no-admin'), $this->handlerExpectingNoHandle());
        self::assertSame(401, $resp1->getStatusCode());
        self::assertSame(401, $resp2->getStatusCode());
    }

    public function testWrongRealmTokenReturns401(): void
    {
        // Validator returns null because iss != admin
        $this->validator->method('validate')->willReturn(null);
        $mw = $this->middleware(allowAll: false);
        $req = $this->request('/admin/realms', 'Bearer jwt-web-realm');
        $resp = $mw->process($req, $this->handlerExpectingNoHandle());
        self::assertSame(401, $resp->getStatusCode());
    }

    public function testTamperedTokenReturns401(): void
    {
        $this->validator->method('validate')->willReturn(null);
        $mw = $this->middleware(allowAll: false);
        $req = $this->request('/admin/realms', 'Bearer invalid.signature.here');
        $resp = $mw->process($req, $this->handlerExpectingNoHandle());
        self::assertSame(401, $resp->getStatusCode());
    }

    public function testStaticViaBearerOnNonOpsPassesWhenAllowAllTrue(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', 'Bearer ' . self::ADMIN_API_KEY, '', allowAll: true, expectPass: true);
    }

    public function testStaticViaBearerOnNonOpsFailsWhenAllowAllFalse(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', 'Bearer ' . self::ADMIN_API_KEY, '', allowAll: false, expectPass: false);
    }

    public function testStaticViaXAdminKeyOnOpsPassesEvenWhenAllowAllFalse(): void
    {
        $this->assertStaticFallbackAccess('/admin/migrations/migrate', '', self::ADMIN_API_KEY, allowAll: false, expectPass: true);
    }

    public function testStaticViaXAdminKeyOnNonOpsFailsWhenAllowAllFalse(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', '', self::ADMIN_API_KEY, allowAll: false, expectPass: false);
    }

    public function testStaticViaXAdminKeyOnNonOpsPassesWhenAllowAllTrue(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', '', self::ADMIN_API_KEY, allowAll: true, expectPass: true);
    }

    public function testNoCredentialsReturns401(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', '', '', allowAll: true, expectPass: false);
    }

    public function testWrongStaticKeyReturns401(): void
    {
        $this->assertStaticFallbackAccess('/admin/realms', 'Bearer wrong-key', '', allowAll: true, expectPass: false);
    }

    public function testJwtPriorityOverStaticWhenBothPresent(): void
    {
        $this->validator->method('validate')->willReturn(['sub' => 'u1', 'realm_access' => ['roles' => ['admin']]]);
        $mw = $this->middleware(allowAll: false);
        // Bearer is JWT, X-Admin-Key is static; JWT should win and pass even on non-ops
        $req = $this->request('/admin/realms', 'Bearer jwt-admin', self::ADMIN_API_KEY);
        $handler = $this->handlerExpectingHandle();
        $resp = $mw->process($req, $handler);
        self::assertNotSame(401, $resp->getStatusCode());
    }

    public function testResponseIsUnauthorizedJsonOnFailure(): void
    {
        $this->validator->method('validate')->willReturn(null);
        $mw = $this->middleware(allowAll: false);
        $req = $this->request('/admin/realms', '', '');
        $resp = $mw->process($req, $this->handlerExpectingNoHandle());
        self::assertSame(401, $resp->getStatusCode());
        $body = json_decode((string) $resp->getBody(), true);
        self::assertSame('unauthorized', $body['error'] ?? null);
    }
}
