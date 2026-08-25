<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Middleware\ValidateAccessToken;
use AuthServer\Models\Realm;
use AuthServer\Services\TokenValidator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ValidateAccessTokenTest extends TestCase
{
    private TokenValidator $tokenValidator;
    private ValidateAccessToken $middleware;
    private Realm $realm;

    protected function setUp(): void
    {
        $this->tokenValidator = $this->createMock(TokenValidator::class);
        $this->middleware = new ValidateAccessToken(
            $this->tokenValidator,
        );
        $this->realm = new Realm(
            'r-id', 'test', 'k-id', 1800, 300, 300, 300, 86400, 1800,
            'openid', '2025-01-01 00:00:00',
        );
    }

    public function testMissingAuthHeaderReturns400(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(Realm::class)->willReturn($this->realm);
        $request->method('getHeaderLine')->with('Authorization')->willReturn('');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('missing authorization header', $body['error_description']);
    }

    public function testNonBearerAuthHeaderReturns400(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(Realm::class)->willReturn($this->realm);
        $request->method('getHeaderLine')->with('Authorization')->willReturn('Basic dGVzdDpwYXNz');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);
        self::assertSame(400, $response->getStatusCode());
    }

    public function testInvalidTokenReturns401(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(Realm::class)->willReturn($this->realm);
        $request->method('getHeaderLine')->with('Authorization')->willReturn('Bearer invalid-token');

        $this->tokenValidator->method('parseValidToken')
            ->willThrowException(new ValidationFailed('Token verification failed'));

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testValidTokenSetsAttributeAndPassesThrough(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(Realm::class)->willReturn($this->realm);
        $request->method('getHeaderLine')->with('Authorization')->willReturn('Bearer valid-token');

        $parsed = ['sub' => 'u-id', 'preferred_username' => 'emant', 'jti' => 'jti-1'];
        $this->tokenValidator->method('parseValidToken')->willReturn($parsed);

        $request->expects(self::once())
            ->method('withAttribute')
            ->with('accessTokenParsed', $parsed)
            ->willReturn($request);

        $response = $this->createMock(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::once())->method('handle')->willReturn($response);

        $result = $this->middleware->process($request, $handler);
        self::assertSame($response, $result);
    }

    public function testValidTokenParsedIsPassedToHandler(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(Realm::class)->willReturn($this->realm);
        $request->method('getHeaderLine')->with('Authorization')->willReturn('Bearer v-tok');

        $parsed = ['sub' => 'u-1', 'jti' => 'jti-2'];
        $this->tokenValidator->method('parseValidToken')->willReturn($parsed);

        $enrichedRequest = $this->createMock(ServerRequestInterface::class);
        $request->method('withAttribute')->willReturn($enrichedRequest);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::once())->method('handle')->with($enrichedRequest);

        $this->middleware->process($request, $handler);
    }
}
