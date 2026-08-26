<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Services\InputValidator;
use PHPUnit\Framework\TestCase;

class InputValidatorTest extends TestCase
{
    // ── validateRedirectUri ────────────────────────────────────

    public function testValidateRedirectUriExactMatch(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'https://example.com');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriSubPathMatchThrows(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'https://example.com/callback');
    }

    public function testValidateRedirectUriMismatchThrows(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'https://other.com');
    }

    public function testValidateRedirectUriExactMatchIgnoresQuery(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'https://example.com?x=1');
    }

    // ── validateRedirectUri — Keycloak-style `*` wildcard (F-44) ─

    public function testValidateRedirectUriRootWildcardAcceptsBareOrigin(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriRootWildcardAcceptsSubroute(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/dashboard');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriRootWildcardAcceptsDeepPathWithQuery(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/a/b/c?foo=1');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriRootWildcardRejectsSiblingHost(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://localhost:5173x/dashboard');
    }

    public function testValidateRedirectUriRootWildcardRejectsOtherScheme(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'https://localhost:5173/dashboard');
    }

    public function testValidateRedirectUriRootWildcardRejectsOtherPort(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://localhost:5174/dashboard');
    }

    public function testValidateRedirectUriRootWildcardRejectsUserinfo(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://user:pass@localhost:5173/dashboard');
    }

    public function testValidateRedirectUriPathWildcardAcceptsSubroute(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/react-playground/dashboard');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriPathWildcardAcceptsZeroLengthAfterSlash(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/react-playground/');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriPathWildcardAcceptsAnyDepth(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/react-playground/a/b/c');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriPathWildcardRejectsSiblingPath(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/react-playgroundx');
    }

    public function testValidateRedirectUriPathWildcardRejectsPathWithoutSlash(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://localhost:5173/react-playground');
    }

    public function testValidateRedirectUriPathWildcardRejectsBareOrigin(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://localhost:5173');
    }

    public function testValidateRedirectUriPathWildcardRejectsSiblingPrefix(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://app.example.com/api/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'https://app.example.com/api-admin/secret');
    }

    // ── validateQueryParams ────────────────────────────────────

    public function testValidateQueryParamsValid(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
        ];
        InputValidator::validateQueryParams($query);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateQueryParamsMissingFieldThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams(['scope' => 'openid']);
    }

    public function testValidateQueryParamsInvalidResponseModeThrows(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'invalid', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
        ];
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams($query);
    }

    public function testValidateQueryParamsMissingOpenidThrows(): void
    {
        $query = [
            'scope' => 'profile', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
        ];
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams($query);
    }

    public function testValidateQueryParamsRejectsNonCodeResponseType(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app',
            'response_mode' => 'query', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
            'response_type' => 'token',
        ];
        $this->expectException(ValidationFailed::class);
        $this->expectExceptionMessage('unsupported response_type');
        InputValidator::validateQueryParams($query);
    }

    public function testValidateQueryParamsAllowsOptionalNonceStateResponseMode(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'redirect_uri' => 'https://example.com',
        ];
        InputValidator::validateQueryParams($query);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateQueryParamsCodeChallengeMethod(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
            'code_challenge_method' => 'S256', 'code_challenge' => 'abc123',
        ];
        InputValidator::validateQueryParams($query);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateQueryParamsUnsupportedCodeChallengeMethodThrows(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'https://example.com',
            'state' => 'st', 'nonce' => 'nc',
            'code_challenge_method' => 'plain',
        ];
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams($query);
    }

    // ── validateTokenParams ────────────────────────────────────

    public function testValidateTokenParamsAuthCode(): void
    {
        InputValidator::validateTokenParams([
            'grant_type' => 'authorization_code', 'client_id' => 'app', 'code' => 'c',
        ]);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateTokenParamsRefreshToken(): void
    {
        InputValidator::validateTokenParams([
            'grant_type' => 'refresh_token', 'client_id' => 'app', 'refresh_token' => 'rt',
        ]);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateTokenParamsClientCredentials(): void
    {
        InputValidator::validateTokenParams([
            'grant_type' => 'client_credentials', 'client_id' => 'app',
        ]);
        $this->expectNotToPerformAssertions();
    }

    public function testValidateTokenParamsMissingGrantTypeThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateTokenParams(['client_id' => 'app']);
    }

    public function testValidateTokenParamsUnsupportedGrantTypeThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateTokenParams([
            'grant_type' => 'implicit', 'client_id' => 'app',
        ]);
    }

    public function testValidateTokenParamsAuthCodeMissingCodeThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateTokenParams([
            'grant_type' => 'authorization_code', 'client_id' => 'app',
        ]);
    }

    public function testValidateTokenParamsRefreshTokenEmptyThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->expectExceptionMessage("missing required field 'refresh_token'");
        InputValidator::validateTokenParams([
            'grant_type' => 'refresh_token', 'client_id' => 'app', 'refresh_token' => '',
        ]);
    }

    public function testValidateTokenParamsRefreshTokenUndefinedStringThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->expectExceptionMessage("missing required field 'refresh_token'");
        InputValidator::validateTokenParams([
            'grant_type' => 'refresh_token', 'client_id' => 'app', 'refresh_token' => 'undefined',
        ]);
    }

    // ── validateClientOrigin ──────────────────────────────────

    public function testValidateClientOriginMatchesOriginOfRegisteredUri(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com/app', false, '2025-01-01 00:00:00');
        InputValidator::validateClientOrigin($client, 'https://example.com');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateClientOriginWithPort(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173', false, '2025-01-01 00:00:00');
        InputValidator::validateClientOrigin($client, 'http://localhost:5173');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateClientOriginWrongHostThrows(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateClientOrigin($client, 'https://evil.com');
    }

    public function testValidateClientOriginWrongSchemeThrows(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateClientOrigin($client, 'http://example.com');
    }

    public function testValidateClientOriginSubPathNotAllowed(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'https://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateClientOrigin($client, 'https://example.com/app');
    }

    // ── validateClientOrigin — path wildcards do not affect origins (F-44) ─

    public function testValidateClientOriginMatchesOriginOfWildcardUri(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        InputValidator::validateClientOrigin($client, 'http://localhost:5173');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateClientOriginMatchesOriginOfPathWildcardUri(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/react-playground/*', false, '2025-01-01 00:00:00');
        InputValidator::validateClientOrigin($client, 'http://localhost:5173');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateClientOriginRejectsSiblingHostOfWildcardUri(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://localhost:5173/*', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateClientOrigin($client, 'http://localhost:5173x');
    }

    // ── validateCodeChallenge ──────────────────────────────────

    public function testValidateCodeChallengeMismatchThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateCodeChallenge('challenge-abc', 'wrong-verifier');
    }

    public function testValidateCodeChallengeMissingVerifierThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateCodeChallenge('challenge-abc', null);
    }
}
