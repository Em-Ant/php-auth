<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Services\InputValidator;
use PHPUnit\Framework\TestCase;

class InputValidatorTest extends TestCase
{
    // ── validateScope ──────────────────────────────────────────

    public function testValidateScopePasses(): void
    {
        self::assertTrue(InputValidator::validateScope(['openid', 'profile'], 'openid'));
    }

    public function testValidateScopeMissingOpenidReturnsFalse(): void
    {
        self::assertFalse(InputValidator::validateScope(['profile'], 'email'));
    }

    public function testValidateScopeUnknownScopeReturnsFalse(): void
    {
        self::assertFalse(InputValidator::validateScope(['openid'], 'openid unknown'));
    }

    // ── validateRedirectUri ────────────────────────────────────

    public function testValidateRedirectUriExactMatch(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://example.com', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://example.com');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriSubPathMatch(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://example.com', false, '2025-01-01 00:00:00');
        InputValidator::validateRedirectUri($client, 'http://example.com/callback');
        $this->expectNotToPerformAssertions();
    }

    public function testValidateRedirectUriMismatchThrows(): void
    {
        $client = new Client('c-1', 'app', 'r-1', null, 'http://example.com', false, '2025-01-01 00:00:00');
        $this->expectException(ValidationFailed::class);
        InputValidator::validateRedirectUri($client, 'http://other.com');
    }

    // ── validateQueryParams ────────────────────────────────────

    public function testValidateQueryParamsValid(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'http://example.com',
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
            'response_mode' => 'invalid', 'redirect_uri' => 'http://example.com',
            'state' => 'st', 'nonce' => 'nc',
        ];
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams($query);
    }

    public function testValidateQueryParamsMissingOpenidThrows(): void
    {
        $query = [
            'scope' => 'profile', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'http://example.com',
            'state' => 'st', 'nonce' => 'nc',
        ];
        $this->expectException(ValidationFailed::class);
        InputValidator::validateQueryParams($query);
    }

    public function testValidateQueryParamsCodeChallengeMethod(): void
    {
        $query = [
            'scope' => 'openid', 'client_id' => 'app', 'response_type' => 'code',
            'response_mode' => 'query', 'redirect_uri' => 'http://example.com',
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
            'response_mode' => 'query', 'redirect_uri' => 'http://example.com',
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

    // ── validateCodeChallenge ──────────────────────────────────

    public function testValidateCodeChallengeMismatchThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        InputValidator::validateCodeChallenge('challenge-abc', 'wrong-verifier');
    }
}
