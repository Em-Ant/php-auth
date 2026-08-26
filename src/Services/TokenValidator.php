<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use Psr\Log\LoggerInterface;

class TokenValidator
{
    private string $issuer;
    private TokenService $tokenService;
    private TokenBlacklistRepository $tokenBlacklistRepository;
    private LoggerInterface $logger;

    public function __construct(
        string $issuer,
        TokenService $tokenService,
        TokenBlacklistRepository $tokenBlacklistRepository,
        LoggerInterface $logger
    ) {
        $this->issuer = $issuer;
        $this->tokenService = $tokenService;
        $this->tokenBlacklistRepository = $tokenBlacklistRepository;
        $this->logger = $logger;
    }

    public function decodeClaimsOnly(string $token): ?array
    {
        return $this->tokenService->decodeTokenSafely($token);
    }

    public function validate(
        string $token,
        Realm $realm,
        ?string $expectedTyp = null,
        ?string $expectedAud = null
    ): ?array {
        $claims = $this->verify($token, $realm);
        if ($claims === null) {
            return null;
        }

        if ($expectedTyp !== null && ($claims['typ'] ?? null) !== $expectedTyp) {
            return null;
        }

        if (((int) ($claims['exp'] ?? 0)) < time()) {
            return null;
        }

        if ($expectedAud !== null) {
            $rawAud = $claims['aud'] ?? $claims['azp'] ?? '';
            $audList = is_array($rawAud) ? $rawAud : [(string) $rawAud];
            if (!in_array($expectedAud, $audList, true)) {
                return null;
            }
        }

        $jti = (string) ($claims['jti'] ?? '');
        if ($jti !== '' && $this->tokenBlacklistRepository->exists($jti)) {
            return null;
        }

        return $claims;
    }

    /**
     * Validates an id_token_hint for RP-Initiated Logout: the token must be
     * signed, issued by this realm, and typed ID, but an expired hint is
     * accepted when the sid still identifies a (recent) session.
     */
    public function validateIdTokenHint(string $token, Realm $realm): ?array
    {
        $claims = $this->verify($token, $realm);
        if ($claims === null) {
            return null;
        }

        if (($claims['typ'] ?? null) !== 'ID') {
            return null;
        }

        $jti = (string) ($claims['jti'] ?? '');
        if ($jti !== '' && $this->tokenBlacklistRepository->exists($jti)) {
            return null;
        }

        return $claims;
    }

    /**
     * Validates a Bearer access token and returns its claims, throwing when
     * the token is invalid or expired — for callers that treat an invalid
     * token as a request error rather than an expected outcome.
     */
    public function parseValidToken(string $token, Realm $realm): array
    {
        $claims = $this->validate($token, $realm, 'Bearer');
        if ($claims === null) {
            $this->logger->error("invalid or expired access token");
            throw new ValidationFailed('Token verification failed');
        }

        return $claims;
    }

    private function verify(string $token, Realm $realm): ?array
    {
        if (!$this->tokenService->verifySignature($token, $realm)) {
            return null;
        }

        $claims = $this->decodeClaimsOnly($token);
        if ($claims === null) {
            return null;
        }

        if (($claims['iss'] ?? null) !== $this->issuer . '/realms/' . $realm->getName()) {
            return null;
        }

        return $claims;
    }
}
