<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;

class InputValidator
{
    /**
     * Keycloak-style redirect URI matching. Default is an exact match
     * (OIDC Core §3.1.2.1, F-33). A trailing `*` on the registered URI opts
     * in to a path wildcard (semantics verified live against Keycloak,
     * keycloak-parity Q3):
     *
     * - the scheme/host/port must match exactly (the wildcard never leaks
     *   across origins);
     * - the requested path may be any depth under the registered prefix;
     * - query strings are allowed;
     * - a zero-length path after the slash matches;
     * - sibling paths and cross-origin URIs are rejected.
     */
    public static function validateRedirectUri(Client $client, string $redirect_uri): void
    {
        if (!self::uriMatches($client->getUri(), $redirect_uri)) {
            throw new ValidationFailed('invalid redirect_uri');
        }
    }

    /**
     * The origin reported by the check-session iframe is scheme://host[:port];
     * it must match the origin of the client's registered URI exactly. Because
     * the `*` wildcard is path-scoped only, it has no effect on origin
     * matching: a client registered with `https://app.example.com/other/*`
     * still allows iframe origin `https://app.example.com`.
     */
    public static function validateClientOrigin(Client $client, string $origin): void
    {
        $clientOrigin = self::originOf($client->getUri());

        if ($clientOrigin === null || $clientOrigin !== $origin) {
            throw new ValidationFailed('invalid origin');
        }
    }

    public static function originOf(string $uri): ?string
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        // parse_url is lenient about malformed authorities
        // (e.g. `localhost:5173x` is read as host `localhost` + port 5173),
        // which a strict host comparison must not accept. Userinfo is
        // rejected too: it defeats host matching and enables parser-mismatch
        // bypasses (Keycloak CVE-2026-7504).
        $authority = self::extractAuthority($uri);
        if (
            $authority === null
            || str_contains($authority, '@')
            || !self::hasValidPort($authority)
        ) {
            return null;
        }

        $port = isset($parts['port']) ? ':' . $parts['port'] : '';

        return $parts['scheme'] . '://' . $parts['host'] . $port;
    }

    private static function extractAuthority(string $uri): ?string
    {
        $afterScheme = strstr($uri, '://');
        if ($afterScheme === false) {
            return null;
        }

        $rest = substr($afterScheme, 3);
        $end = strcspn($rest, '/?#');

        return substr($rest, 0, $end);
    }

    private static function hasValidPort(string $authority): bool
    {
        $colonPos = strrpos($authority, ':');
        if ($colonPos === false) {
            return true;
        }

        return ctype_digit(substr($authority, $colonPos + 1));
    }

    private static function uriMatches(string $registered, string $requested): bool
    {
        if ($registered === $requested) {
            return true;
        }

        $wildcardMatch = str_ends_with($registered, '*')
            && self::originOf($registered) === self::originOf($requested)
            && self::pathMatches($registered, $requested);

        return $wildcardMatch;
    }

    private static function pathMatches(string $registered, string $requested): bool
    {
        $registeredParts = parse_url($registered);
        $requestedParts = parse_url($requested);
        if ($registeredParts === false || $requestedParts === false) {
            return false;
        }

        $prefix = rtrim($registeredParts['path'] ?? '/', '*');
        $requestedPath = $requestedParts['path'] ?? '/';

        return str_starts_with($requestedPath, $prefix);
    }

    public static function validateQueryParams(array $query): void
    {
        $required_fields = [
            'scope',
            'client_id',
            'response_type',
            'redirect_uri',
        ];

        $code_challenge_method = $query['code_challenge_method'] ?? null;
        if ($code_challenge_method !== null) {
            if ($code_challenge_method !== 'S256') {
                throw new ValidationFailed('unsupported code challenge method');
            }
            $required_fields[] = 'code_challenge';
        }

        self::validateParams($query, $required_fields);

        if (($query['response_type'] ?? '') !== 'code') {
            throw OAuth2Error::unsupportedResponseType('unsupported response_type');
        }

        $response_mode = $query['response_mode'] ?? 'query';
        if (!in_array($response_mode, ['fragment', 'query'])) {
            throw new ValidationFailed('invalid response mode');
        }

        if (!in_array('openid', explode(' ', $query['scope']))) {
            throw OAuth2Error::invalidScope('invalid scope');
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
            throw OAuth2Error::unsupportedGrantType('unsupported flow');
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
            throw OAuth2Error::invalidGrant('invalid code_verifier');
        }
        if ($code_challenge !== Base64Utils::b64UrlEncode(hash('sha256', $code_verifier, true))) {
            throw OAuth2Error::invalidGrant('code_verifier does not match code_challenge');
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
