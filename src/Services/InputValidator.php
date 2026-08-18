<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;

class InputValidator
{
    public static function validateRedirectUri(Client $client, string $redirect_uri): void
    {
        $_redirect_uri = rtrim($redirect_uri, '/');
        $_client_uri = rtrim($client->getUri(), '/');

        if (
            $_redirect_uri !== $_client_uri &&
            !str_starts_with($_redirect_uri, $_client_uri . '/')
        ) {
            throw new ValidationFailed('invalid redirect_uri');
        }
    }

    /**
     * The origin reported by the check-session iframe is scheme://host[:port];
     * it must match the origin of the client's registered URI exactly.
     */
    public static function validateClientOrigin(Client $client, string $origin): void
    {
        $clientOrigin = self::extractOrigin($client->getUri());

        if ($clientOrigin === null || $clientOrigin !== $origin) {
            throw new ValidationFailed('invalid origin');
        }
    }

    private static function extractOrigin(string $uri): ?string
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $port = isset($parts['port']) ? ':' . $parts['port'] : '';

        return $parts['scheme'] . '://' . $parts['host'] . $port;
    }

    public static function validateQueryParams(array $query): void
    {
        $required_fields = [
            'scope',
            'client_id',
            'response_type',
            'response_mode',
            'redirect_uri',
            'state',
            'nonce',
        ];

        $code_challenge_method = $query['code_challenge_method'] ?? null;
        if ($code_challenge_method !== null) {
            if ($code_challenge_method !== 'S256') {
                throw new ValidationFailed('unsupported code challenge method');
            }
            $required_fields[] = 'code_challenge';
        }

        self::validateParams($query, $required_fields);

        if (!in_array($query['response_mode'], ['fragment', 'query'])) {
            throw new ValidationFailed('invalid response mode');
        }

        if (!in_array('openid', explode(' ', $query['scope']))) {
            throw new ValidationFailed('invalid scope');
        }
    }

    public static function validateTokenParams(array $query): void
    {
        $required_fields = [
            'grant_type',
            'client_id',
        ];

        self::validateParams($query, $required_fields);

        $grantType = GrantType::tryFrom($query['grant_type']);
        if ($grantType === null) {
            throw new ValidationFailed('unsupported flow');
        }

        if ($grantType === GrantType::AuthorizationCode && !isset($query['code'])) {
            throw new ValidationFailed("missing required field 'code'");
        }
        if ($grantType === GrantType::RefreshToken) {
            $rt = $query['refresh_token'] ?? '';
            if ($rt === '' || trim($rt) === '' || $rt === 'undefined') {
                throw new ValidationFailed("missing required field 'refresh_token'");
            }
        }
    }

    public static function validateCodeChallenge(?string $code_challenge, ?string $code_verifier): void
    {
        if ($code_verifier === null) {
            throw new ValidationFailed('invalid code_verifier');
        }
        if ($code_challenge !== Base64Utils::b64UrlEncode(hash('sha256', $code_verifier, true))) {
            throw new ValidationFailed('code_verifier does not match code_challenge');
        }
    }

    private static function validateParams(array $params, array $required_fields): void
    {
        $missing = [];

        foreach ($required_fields as $f) {
            if (!isset($params[$f]) || $params[$f] === ' ') {
                $missing[] = $f;
            }
        }

        if (count($missing) > 0) {
            $missing_str = implode(', ', $missing);
            $s = count($missing) > 1 ? 's' : '';
            throw new ValidationFailed("missing required parameter$s ($missing_str)");
        }
    }
}
