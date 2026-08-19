<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Tests\Support\FailingPdo;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * Verifies the repository error contract from the HTTP surface: a storage
 * failure must surface as 500, never as a 400 that pretends data was missing.
 */
class StorageFailureTest extends TestCase
{
    public function testTokenEndpointReturns500OnStorageFailure(): void
    {
        $app = TestAppFactory::createApp([
            ILoginRepo::class => new LoginRepository(new FailingPdo()),
        ]);

        $request = (new ServerRequestFactory())->createServerRequest(
            'POST',
            '/realms/web/protocol/openid-connect/token'
        );
        $request->getBody()->write(http_build_query([
            'grant_type' => 'authorization_code',
            'code' => 'any-code',
            'client_id' => 'playground',
            'redirect_uri' => 'http://localhost:5173/react-playground/',
        ]));
        $request->getBody()->rewind();
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $response = $app->handle($request);

        self::assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('server_error', $body['error'] ?? null);
    }

    public function testAuthEndpointClientLookupFailureIsNot400(): void
    {
        $app = TestAppFactory::createApp([
            IClientRepo::class => new ClientRepository(new FailingPdo()),
        ]);

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            '/realms/web/protocol/openid-connect/auth?' . http_build_query([
                'client_id' => 'playground',
                'redirect_uri' => 'http://localhost:5173/react-playground/',
                'response_type' => 'code',
                'response_mode' => 'query',
                'scope' => 'openid',
                'state' => 'st',
                'nonce' => 'nc',
            ])
        );

        $response = $app->handle($request);

        self::assertNotSame(400, $response->getStatusCode());
        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString(
            '/realms/web/protocol/openid-connect/error?e=',
            $response->getHeaderLine('Location')
        );
    }
}
