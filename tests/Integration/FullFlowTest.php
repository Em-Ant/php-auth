<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Controllers\Authorize as AuthorizeController;
use AuthServer\Middleware\CorsMiddleware;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\RequestLogger;
use AuthServer\Middleware\ValidateAccessToken;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\RealmRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthorizeService;
use AuthServer\Services\FilesystemKeyStore;
use AuthServer\Services\InMemorySessionCookieHandler;
use AuthServer\Services\LoginStateMachine;
use AuthServer\Services\SecretsService;
use AuthServer\Services\TokenService;
use AuthServer\Services\ViewRenderer;
use DI\Bridge\Slim\Bridge;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;

class FullFlowTest extends TestCase
{
    private static DataSource $dataSource;
    private static \Slim\App $app;
    private static string $issuer = 'http://localhost:8000';

    public static function setUpBeforeClass(): void
    {
        $pdo = new \PDO('sqlite::memory:', '', '', [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $pdo->exec('PRAGMA foreign_keys = ON');

        $schema = file_get_contents(__DIR__ . '/../../db/init_v1.sql');
        $pdo->exec($schema);

        $seed = file_get_contents(__DIR__ . '/../../db/seed.sql');
        $pdo->exec($seed);

        DataSource::createInstance($pdo);
        self::$dataSource = DataSource::getInstance();

        $logger = new class implements LoggerInterface {
            public function emergency($message, array $context = []): void {}
            public function alert($message, array $context = []): void {}
            public function critical($message, array $context = []): void {}
            public function error($message, array $context = []): void {}
            public function warning($message, array $context = []): void {}
            public function notice($message, array $context = []): void {}
            public function info($message, array $context = []): void {}
            public function debug($message, array $context = []): void {}
            public function log($level, $message, array $context = []): void {}
        };

        $config = parse_ini_file(__DIR__ . '/../../config.ini', true);
        $GLOBALS['sub_path'] = $config['server']['base_path'] ?? '';

        $keyStore = new FilesystemKeyStore(__DIR__ . '/../../keys');
        $tokenService = new TokenService(self::$issuer, $keyStore);

        $passwordHashing = $config['password_hashing'] ?? [];
        $secretsService = new SecretsService($passwordHashing);

        $clientRepo = new ClientRepository(self::$dataSource, $logger);
        $sessionRepo = new SessionRepository(self::$dataSource, $logger);
        $loginRepo = new LoginRepository(self::$dataSource, $logger);
        $userRepo = new UserRepository(self::$dataSource, $logger);
        $realmRepo = new RealmRepository(self::$dataSource, $logger);
        $realmProvider = new RealmProvider($realmRepo);

        $loginStateMachine = new LoginStateMachine($loginRepo, $logger);

        $authService = new AuthorizeService(
            $clientRepo, $sessionRepo, $userRepo, $loginRepo,
            $loginStateMachine, $secretsService, $tokenService, $logger,
        );

        $sessionCookieHandler = new InMemorySessionCookieHandler();

        $viewRenderer = new ViewRenderer(
            __DIR__ . '/../../src/views',
            'template.php',
        );

        $authController = new AuthorizeController(
            $authService,
            self::$issuer,
            $GLOBALS['sub_path'],
            $keyStore,
            $sessionCookieHandler,
            $viewRenderer,
        );

        $container = new \DI\Container();
        $container->set(AuthorizeController::class, $authController);

        self::$app = Bridge::create($container);
        self::$app->setBasePath($config['server']['base_path'] ?? '');

        $errorMiddleware = self::$app->addErrorMiddleware(true, true, true);
        $errorMiddleware->setErrorHandler(
            HttpNotFoundException::class,
            function (ServerRequestInterface $request, \Throwable $exception) use ($logger) {
                $response = new Response();
                return JsonResponse::error($response, 'not found', $exception->getMessage(), 404);
            }
        );

        self::$app->add(function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
            $ct = $request->getHeaderLine('Content-Type');
            $rawBody = (string) $request->getBody();

            if ($request->getMethod() === 'POST' && $rawBody !== '') {
                if (str_contains($ct, 'application/json')) {
                    $data = json_decode($rawBody, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $request = $request->withParsedBody($data ?? []);
                    }
                } elseif (str_contains($ct, 'application/x-www-form-urlencoded')) {
                    parse_str($rawBody, $data);
                    $request = $request->withParsedBody($data);
                }
            }
            return $handler->handle($request);
        });

        self::$app->add(new CorsMiddleware());
        self::$app->add(new RequestLogger($logger));

        self::$app->group(
            '/realms/{realm}/protocol/openid-connect',
            function (\Slim\Routing\RouteCollectorProxy $group) use ($authController, $authService) {
                $group->get('/auth', [$authController, 'authorize']);
                $group->post('/login-actions/authenticate', [$authController, 'login']);
                $group->post('/token', [$authController, 'token']);
                $group->get('/logout', [$authController, 'logout']);
                $group->get('/error', [$authController, 'error']);
                $group->get('/certs', [$authController, 'sendKeys']);
                $group->get('/userinfo', [$authController, 'sendUserInfo'])
                    ->add(new ValidateAccessToken($authService));
            }
        )->add($realmProvider);

        self::$app->get('/realms/{realm}/.well-known/openid-configuration', [$authController, 'sendConfig'])
            ->add($realmProvider);
    }

    private function createRequest(string $method, string $path, array $query = [], mixed $body = null, array $headers = []): ServerRequestInterface
    {
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

    // ── Auth endpoint renders login form ─────────────────────

    public function testAuthEndpointReturnsLoginForm(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);

        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('login', $body);
    }

    // ── Auth fails with invalid client ────────────────────────

    public function testAuthWithInvalidClientReturns400(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'ghost',
            'redirect_uri' => 'http://example.com',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }

    // ── Full login flow ───────────────────────────────────────

    public function testLoginWithWrongPasswordShowsForm(): void
    {
        // Step 1: GET /auth to get login form
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in form');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in form');
        $csrfToken = $m[1];

        // Step 2: POST login with wrong password
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'wrong-password',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('invalid password', $body);
    }

    public function testFullLoginFlow(): array
    {
        // Step 1: GET /auth
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found');
        $csrfToken = $m[1];

        // Step 2: POST login with correct password
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173?code=', $location);
        self::assertStringContainsString('&state=st', $location);

        preg_match('/code=([^&]+)/', $location, $m);
        self::assertNotEmpty($m, 'code not found');
        $code = $m[1];

        // Step 3: POST token to exchange code
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $tokens = json_decode((string) $response->getBody(), true);
        self::assertNotNull($tokens);
        self::assertArrayHasKey('access_token', $tokens);
        self::assertArrayHasKey('refresh_token', $tokens);
        self::assertArrayHasKey('id_token', $tokens);
        self::assertSame('Bearer', $tokens['token_type']);
        self::assertSame(300, $tokens['expires_in']);

        // Return tokens for subsequent dependent tests
        return $tokens;
    }

    #[Depends('testFullLoginFlow')]
    public function testRefreshTokenFlow(array $tokens): void
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'code' => '',
            'redirect_uri' => '',
            'refresh_token' => $tokens['refresh_token'],
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('access_token', $body);
        self::assertArrayHasKey('refresh_token', $body);

        // Token rotation: new refresh token differs from old
        self::assertNotSame($tokens['refresh_token'], $body['refresh_token']);
    }

    // ── Certs endpoint ────────────────────────────────────────

    public function testCertsEndpointReturnsJwks(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/certs');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('keys', $body);
        self::assertCount(1, $body['keys']);
        self::assertSame('RS256', $body['keys'][0]['alg']);
    }

    // ── Well-known endpoint ───────────────────────────────────

    public function testWellKnownEndpoint(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertStringContainsString(self::$issuer . '/realms/test', $body['issuer']);
    }

    // ── UserInfo endpoint ─────────────────────────────────────

    #[Depends('testFullLoginFlow')]
    public function testUserInfoReturnsSubAndUsername(array $tokens): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('sub', $body);
        self::assertArrayHasKey('preferred_username', $body);
        self::assertSame('emant_test', $body['preferred_username']);
    }

    // ── Logout endpoint ───────────────────────────────────────

    #[Depends('testFullLoginFlow')]
    public function testLogoutExpiresSession(array $tokens): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/logout', [
            'id_token_hint' => $tokens['id_token'],
            'post_logout_redirect_uri' => 'http://localhost:5173',
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        self::assertStringStartsWith('http://localhost:5173', $response->getHeaderLine('Location'));
    }

    // ── PKCE flow ─────────────────────────────────────────────

    public function testPkceFlow(): void
    {
        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Step 1: GET /auth with code_challenge
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'pkce-st',
            'nonce' => 'pkce-nc',
            'code_challenge_method' => 'S256',
            'code_challenge' => $codeChallenge,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        $loginId = $m[1];
        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        $csrfToken = $m[1];

        // Step 2: POST login
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        preg_match('/code=([^&]+)/', $response->getHeaderLine('Location'), $m);
        $pkceCode = $m[1];

        // Step 3: Exchange code with verifier
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $pkceCode,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
            'code_verifier' => $codeVerifier,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertArrayHasKey('access_token', $tokens);
    }

    // ── SSO: no session cookie → shows login form ─────────────

    public function testSsoWithoutCookieShowsLoginForm(): void
    {
        $request = $this->createRequest('GET', '/realms/web/protocol/openid-connect/auth', [
            'client_id' => 'playground',
            'redirect_uri' => 'https://em-ant.gitlab.io/react-playground',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'sso-st',
            'nonce' => 'sso-nc',
        ]);

        $response = $this->handle($request);
        $body = (string) $response->getBody();
        self::assertStringContainsString('login', $body);
    }
}
