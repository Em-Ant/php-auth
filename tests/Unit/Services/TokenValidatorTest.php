<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Models\KeySet;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use AuthServer\Services\TokenService;
use AuthServer\Services\TokenValidator;
use PHPUnit\Framework\TestCase;

class TokenValidatorTest extends TestCase
{
    private const KID = '33ce4036-0a36-45b9-ba74-6087d03c3b35';
    private const ISSUER = 'http://localhost:8000';

    private TokenValidator $validator;
    private TokenService $tokenService;
    private TokenBlacklistRepository $blacklist;
    private Realm $realm;

    protected function setUp(): void
    {
        $keysDir = __DIR__ . '/../../../keys/' . self::KID;
        $keySet = new KeySet(
            publicKey: file_get_contents("$keysDir/public_key.pem"),
            privateKey: file_get_contents("$keysDir/private_key.pem"),
            cert: file_get_contents("$keysDir/cert.pem"),
            jwks: json_decode(file_get_contents("$keysDir/keys.json"), true),
        );

        $keyStore = new class ($keySet) implements KeyStore {
            public function __construct(private KeySet $keySet) {}
            public function findKeys(string $kid): KeySet
            {
                return $this->keySet;
            }
        };

        $this->tokenService = new TokenService(self::ISSUER, $keyStore);
        $this->blacklist = $this->createMock(TokenBlacklistRepository::class);
        $this->blacklist->method('exists')->willReturn(false);

        $this->validator = new TokenValidator(
            self::ISSUER,
            $this->tokenService,
            $this->blacklist,
        );

        $this->realm = new Realm(
            id: 'r-id',
            name: 'test',
            keys_id: self::KID,
            refresh_token_expires_in: 1800,
            access_token_expires_in: 300,
            pending_login_expires_in: 300,
            authenticated_login_expires_in: 300,
            session_expires_in: 86400,
            idle_session_expires_in: 1800,
            scope: 'openid profile',
            created_at: '2025-01-01 00:00:00',
        );
    }

    private function createToken(array $payload): string
    {
        return $this->tokenService->createToken($payload, self::KID);
    }

    private function validPayload(string $typ = 'Bearer', string $aud = 'my-app'): array
    {
        return [
            'typ' => $typ,
            'iss' => self::ISSUER . '/realms/test',
            'aud' => $aud,
            'exp' => time() + 300,
            'iat' => time(),
            'jti' => 'jti-1',
            'sub' => 'user-1',
        ];
    }

    public function testValidateReturnsClaimsForValidToken(): void
    {
        $claims = $this->validator->validate(
            $this->createToken($this->validPayload()),
            $this->realm,
            'Bearer',
            'my-app'
        );

        self::assertIsArray($claims);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('Bearer', $claims['typ']);
    }

    public function testValidateRejectsWrongType(): void
    {
        $token = $this->createToken($this->validPayload('Bearer'));

        self::assertNull(
            $this->validator->validate($token, $this->realm, 'ID')
        );
    }

    public function testValidateAllowsAnyTypeWhenTypeNotConstrained(): void
    {
        $token = $this->createToken($this->validPayload('ID'));

        $claims = $this->validator->validate($token, $this->realm);
        self::assertSame('ID', $claims['typ']);
    }

    public function testValidateRejectsTamperedToken(): void
    {
        $token = $this->createToken($this->validPayload());
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.invalidsignature';

        self::assertNull($this->validator->validate($tampered, $this->realm));
    }

    public function testValidateRejectsExpiredToken(): void
    {
        $payload = $this->validPayload();
        $payload['exp'] = time() - 1;

        self::assertNull($this->validator->validate($this->createToken($payload), $this->realm));
    }

    public function testValidateRejectsMissingExpiry(): void
    {
        $payload = $this->validPayload();
        unset($payload['exp']);

        self::assertNull($this->validator->validate($this->createToken($payload), $this->realm));
    }

    public function testValidateRejectsWrongIssuer(): void
    {
        $payload = $this->validPayload();
        $payload['iss'] = 'https://evil.example/realms/test';

        self::assertNull($this->validator->validate($this->createToken($payload), $this->realm));
    }

    public function testValidateRejectsWrongAudience(): void
    {
        $token = $this->createToken($this->validPayload('Bearer', 'my-app'));

        self::assertNull(
            $this->validator->validate($token, $this->realm, 'Bearer', 'other-client')
        );
    }

    public function testValidateAcceptsAzpAsAudienceFallback(): void
    {
        $payload = $this->validPayload();
        unset($payload['aud']);
        $payload['azp'] = 'my-app';

        $claims = $this->validator->validate(
            $this->createToken($payload),
            $this->realm,
            'Bearer',
            'my-app'
        );

        self::assertIsArray($claims);
        self::assertSame('my-app', $claims['azp']);
    }

    public function testValidateRejectsBlacklistedToken(): void
    {
        $this->blacklist = $this->createMock(TokenBlacklistRepository::class);
        $this->blacklist->method('exists')->willReturn(true);
        $this->validator = new TokenValidator(
            self::ISSUER,
            $this->tokenService,
            $this->blacklist,
        );

        self::assertNull(
            $this->validator->validate($this->createToken($this->validPayload()), $this->realm)
        );
    }

    public function testValidateRejectsMalformedToken(): void
    {
        self::assertNull($this->validator->validate('not-a-jwt', $this->realm));
    }

    public function testDecodeClaimsOnlyReturnsClaimsForAnyJwt(): void
    {
        $claims = $this->validator->decodeClaimsOnly($this->createToken($this->validPayload()));

        self::assertSame('user-1', $claims['sub']);
    }

    public function testDecodeClaimsOnlyReturnsNullForMalformedToken(): void
    {
        self::assertNull($this->validator->decodeClaimsOnly('not-a-jwt'));
    }

    // ── validateIdTokenHint (RP-Initiated Logout) ─────────────

    public function testValidateIdTokenHintAcceptsExpiredToken(): void
    {
        $payload = $this->validPayload('ID', 'my-app');
        $payload['exp'] = time() - 1;
        $payload['sid'] = 'session-1';

        $claims = $this->validator->validateIdTokenHint($this->createToken($payload), $this->realm);

        self::assertIsArray($claims);
        self::assertSame('session-1', $claims['sid']);
    }

    public function testValidateIdTokenHintRejectsAccessToken(): void
    {
        $token = $this->createToken($this->validPayload('Bearer'));

        self::assertNull($this->validator->validateIdTokenHint($token, $this->realm));
    }

    public function testValidateIdTokenHintRejectsTamperedToken(): void
    {
        $token = $this->createToken($this->validPayload('ID'));
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.invalidsignature';

        self::assertNull($this->validator->validateIdTokenHint($tampered, $this->realm));
    }

    public function testValidateIdTokenHintRejectsForeignIssuer(): void
    {
        $payload = $this->validPayload('ID');
        $payload['iss'] = 'https://evil.example/realms/test';

        self::assertNull($this->validator->validateIdTokenHint($this->createToken($payload), $this->realm));
    }
}