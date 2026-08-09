<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

trait IntegrationFlowTrait
{
    private function createRequest(
        string $method,
        string $path,
        array $query = [],
        mixed $body = null,
        array $headers = []
    ): ServerRequestInterface {
        $uri = $path;
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($body !== null) {
            $request->getBody()->write(is_string($body) ? $body : http_build_query($body));
            $request->getBody()->rewind();
            if (!is_string($body)) {
                $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
            }
        }

        return $request;
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    private function doFullLogin(string $state = 'fl-st', string $nonce = 'fl-nc'): array
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => $state,
            'nonce' => $nonce,
        ]);
        $response = $this->handle($request);
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in auth response');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in auth response');
        $csrfToken = $m[1];

        $request = $this->createRequest(
            'POST',
            '/realms/test/protocol/openid-connect/login-actions/authenticate',
            ['q' => $loginId],
            [
                'email' => 'test@example.com',
                'password' => 'tst',
                'csrf_token' => $csrfToken,
            ]
        );
        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode(), 'login should redirect');
        $location = $response->getHeaderLine('Location');
        preg_match('/code=([^&]+)/', $location, $m);
        self::assertNotEmpty($m, 'code not found in login redirect');
        $code = $m[1];

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
        ]);
        $response = $this->handle($request);
        return json_decode((string) $response->getBody(), true);
    }
}
