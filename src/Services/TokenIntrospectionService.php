<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use Psr\Log\LoggerInterface;

class TokenIntrospectionService
{
    private ILoginRepo $loginRepository;
    private ClientAuthenticator $clientAuthenticator;
    private TokenService $tokenService;
    private TokenBlacklistRepository $tokenBlacklistRepository;
    private LoggerInterface $logger;

    public function __construct(
        ILoginRepo $loginRepo,
        ClientAuthenticator $clientAuthenticator,
        TokenService $tokenService,
        TokenBlacklistRepository $tokenBlacklistRepository,
        LoggerInterface $logger
    ) {
        $this->loginRepository = $loginRepo;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->tokenService = $tokenService;
        $this->tokenBlacklistRepository = $tokenBlacklistRepository;
        $this->logger = $logger;
    }

    public function introspect(array $params, Realm $realm): array
    {
        $token = $params['token'] ?? '';
        if ($token === '') {
            $this->logger->info('introspect: token parameter missing');
            throw new ValidationFailed('missing required parameter (token)');
        }

        $clientId = $params['client_id'] ?? '';
        $this->validateIntrospectClient($clientId, $params);

        $decoded = $this->tokenService->decodeTokenSafely($token);
        if ($decoded === null) {
            return ['active' => false];
        }

        $typ = $decoded['typ'] ?? '';

        if ($typ === 'Refresh') {
            return $this->introspectRefreshToken($token, $decoded, $realm);
        }

        return $this->introspectAccessToken($token, $decoded, $realm);
    }

    private function validateIntrospectClient(string $clientId, array $params): void
    {
        $client = $this->clientAuthenticator->authenticate($clientId, $params);
        if ($client === null) {
            $this->logger->info("introspect: client $clientId authentication failed");
            throw new AuthenticationFailed('invalid client');
        }
    }

    private function introspectRefreshToken(string $token, array $decoded, Realm $realm): array
    {
        $login = $this->loginRepository->findByRefreshToken($token);
        if ($login === null || $login->getStatus() !== LoginStatus::Active) {
            return ['active' => false];
        }

        $exp = $decoded['exp'] ?? 0;
        if ($exp < time()) {
            return ['active' => false];
        }

        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $exp,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $decoded['jti'] ?? '',
            'token_type' => 'refresh_token',
            'client_id' => $login->getClientId(),
            'scope' => $login->getScope(),
            'sid' => $decoded['sid'] ?? '',
        ];
    }

    private function introspectAccessToken(string $token, array $decoded, Realm $realm): array
    {
        $isValid = $this->tokenService->validateToken($token, $realm);
        if (!$isValid) {
            return ['active' => false];
        }

        $exp = $decoded['exp'] ?? 0;
        if ($exp < time()) {
            return ['active' => false];
        }

        $jti = $decoded['jti'] ?? '';
        if ($jti !== '' && $this->tokenBlacklistRepository->exists($jti)) {
            return ['active' => false];
        }

        $typ = $decoded['typ'] ?? 'Bearer';

        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $exp,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $jti,
            'token_type' => $typ,
            'client_id' => $decoded['azp'] ?? $decoded['aud'] ?? '',
            'scope' => $decoded['scope'] ?? '',
            'sid' => $decoded['sid'] ?? '',
        ];
    }
}
