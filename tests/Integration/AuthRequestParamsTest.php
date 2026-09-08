<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Services\InMemorySessionCookieHandler;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

/**
 * F-43 hardening batch: login_hint / max_age / ui_locales on the
 * authorization endpoint, WWW-Authenticate on userinfo 401s.
 */
class AuthRequestParamsTest extends TestCase
{
    use IntegrationFlowTrait;

    private static \Slim\App $app;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
    }

    private function authQuery(array $extra = []): array
    {
        return array_merge([
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ], $extra);
    }

    private function resetSessionCookie(): void
    {
        $handler = self::$app->getContainer()->get(SessionCookieHandler::class);
        if ($handler instanceof InMemorySessionCookieHandler) {
            $handler->reset();
        }
    }

    /**
     * Ages every session row so max_age checks see them as stale (the
     * shared in-memory DB is fine: each test establishes its own session).
     */
    private function ageAllSessions(int $secondsAgo): void
    {
        $pdo = self::$app->getContainer()->get(\PDO::class);
        $old = gmdate('Y-m-d H:i:s', time() - $secondsAgo);
        $pdo->exec("UPDATE sessions SET created_at = '$old' WHERE created_at IS NOT NULL");
    }

    private function parseLoginForm(string $body): array
    {
        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in login form');
        $loginId = $m[1];
        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in login form');

        return ['loginId' => $loginId, 'csrfToken' => $m[1]];
    }

    private function getAuthPage(array $extra = []): \Psr\Http\Message\ResponseInterface
    {
        $request = $this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/auth',
            $this->authQuery($extra)
        );

        return $this->handle($request);
    }

    private function establishSession(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage(['state' => 'sess-st', 'nonce' => 'sess-nc']);
        self::assertSame(200, $response->getStatusCode());
        $form = $this->parseLoginForm((string) $response->getBody());

        $request = $this->createRequest(
            'POST',
            '/realms/test/protocol/openid-connect/login-actions/authenticate',
            ['q' => $form['loginId']],
            ['email' => 'test@example.com', 'password' => 'tst', 'csrf_token' => $form['csrfToken']]
        );
        $loginResponse = $this->handle($request);
        self::assertSame(302, $loginResponse->getStatusCode());
    }

    public function testLoginHintPrefillsEmailField(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage(['login_hint' => 'hinted@example.com']);

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('value="hinted@example.com"', (string) $response->getBody());
    }

    public function testUiLocalesSetsHtmlLang(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage(['ui_locales' => 'fr-CA fr']);

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('<html lang="fr-CA">', (string) $response->getBody());
    }

    public function testUiLocalesDefaultsToEnglish(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage();

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('<html lang="en">', (string) $response->getBody());
    }

    public function testUiLocalesPersistsAcrossFailedLogin(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage(['ui_locales' => 'fr-CA fr']);
        $body = (string) $response->getBody();
        self::assertStringContainsString('<html lang="fr-CA">', $body);
        self::assertStringContainsString('ui_locales=fr-CA', $body);

        preg_match('/action="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'form action not found');
        // Browsers decode entity-encoded attribute values before navigating.
        $action = html_entity_decode($m[1], ENT_QUOTES, 'UTF-8');

        $form = $this->parseLoginForm($body);
        $request = $this->createRequest(
            'POST',
            $action,
            [],
            ['email' => 'wrong@example.com', 'password' => 'bad', 'csrf_token' => $form['csrfToken']]
        );
        $errorResponse = $this->handle($request);

        self::assertSame(200, $errorResponse->getStatusCode());
        $errorBody = (string) $errorResponse->getBody();
        self::assertStringContainsString('<html lang="fr-CA">', $errorBody);
        self::assertStringContainsString('ui_locales=fr-CA', $errorBody);
    }

    public function testInvalidMaxAgeReturns400(): void
    {
        $this->resetSessionCookie();
        $response = $this->getAuthPage(['max_age' => 'soon']);

        self::assertSame(400, $response->getStatusCode());
    }

    public function testFreshSessionSatisfiesMaxAge(): void
    {
        $this->establishSession();

        $response = $this->getAuthPage(['state' => 'max-fresh', 'max_age' => '3600']);

        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString('code=', $response->getHeaderLine('Location'));
    }

    public function testStaleSessionViolatesMaxAge(): void
    {
        $this->establishSession();
        $this->ageAllSessions(7200);

        $response = $this->getAuthPage(['state' => 'max-stale', 'max_age' => '3600']);

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('login', (string) $response->getBody());
    }

    public function testFreshSessionWithPromptNoneSatisfiesMaxAge(): void
    {
        $this->establishSession();

        $response = $this->getAuthPage(['state' => 'pn-max-fresh', 'max_age' => '3600', 'prompt' => 'none']);

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173?code=', $location);
        self::assertStringContainsString('state=pn-max-fresh', $location);
        self::assertStringNotContainsString('error=', $location);
    }

    public function testStaleSessionWithPromptNoneReturnsLoginRequired(): void
    {
        $this->establishSession();
        $this->ageAllSessions(7200);

        $response = $this->getAuthPage(['state' => 'pn-max-stale', 'max_age' => '3600', 'prompt' => 'none']);

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173', $location);
        self::assertStringContainsString('error=login_required', $location);
        self::assertStringContainsString('state=pn-max-stale', $location);
        self::assertStringNotContainsString('code=', $location);
    }

    public function testUserinfoMissingTokenReturns401WithChallenge(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo');
        $response = self::$app->handle($request);

        self::assertSame(401, $response->getStatusCode());
        $challenge = $response->getHeaderLine('WWW-Authenticate');
        self::assertStringStartsWith('Bearer realm="test"', $challenge);
        self::assertStringContainsString('error="invalid_token"', $challenge);
    }

    public function testUserinfoInvalidTokenReturns401WithChallenge(): void
    {
        $request = $this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/userinfo',
            [],
            null,
            ['Authorization' => 'Bearer invalid-token']
        );
        $response = self::$app->handle($request);

        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testNoPoweredByHeaderOnResponses(): void
    {
        $request = $this->createRequest('GET', '/health');
        $response = self::$app->handle($request);

        self::assertFalse($response->hasHeader('X-Powered-By'));
    }
}
