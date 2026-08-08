<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class TokenIntrospectionService
{
    private ILoginRepo $loginRepository;
    private ClientAuthenticator $clientAuthenticator;
    private TokenValidator $tokenValidator;
    private LoggerInterface $logger;

    public function __construct(
        ILoginRepo $loginRepo,
        ClientAuthenticator $clientAuthenticator,
        TokenValidator $tokenValidator,
        LoggerInterface $logger
    ) {
        $this->loginRepository = $loginRepo;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->tokenValidator = $tokenValidator;
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

        $claims = $this->tokenValidator->validate($token, $realm);
        if ($claims === null) {
            return ['active' => false];
        }

        $typ = $claims['typ'] ?? '';

        if ($typ === 'Refresh') {
            return $this->introspectRefreshToken($token, $claims);
        }

        return $this->introspectAccessToken($claims);
    }

    private function validateIntrospectClient(string $clientId, array $params): void
    {
        $client = $this->clientAuthenticator->authenticate($clientId, $params);
        if ($client === null) {
            $this->logger->info("introspect: client $clientId authentication failed");
            throw new AuthenticationFailed('invalid client');
        }
    }

    private function introspectRefreshToken(string $token, array $decoded): array
    {
        $login = $this->loginRepository->findByRefreshToken($token);
        if ($login === null || $login->getStatus() !== LoginStatus::Active) {
            return ['active' => false];
        }

        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $decoded['exp'] ?? 0,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $decoded['jti'] ?? '',
            'token_type' => 'refresh_token',
            'client_id' => $login->getClientId(),
            'scope' => $login->getScope(),
            'sid' => $decoded['sid'] ?? '',
        ];
    }

    private function introspectAccessToken(array $decoded): array
    {
        $exp = $decoded['exp'] ?? 0;
        $jti = $decoded['jti'] ?? '';
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
