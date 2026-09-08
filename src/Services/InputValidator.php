<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;

/**
 * Static input validation and parsing for request parameters.
 *
 * The `validate*` methods throw ValidationFailed on bad input. The `parse*`
 * methods normalize optional OIDC parameters and are intentionally
 * inconsistent about failure: parseMaxAge throws on malformed values (the
 * spec requires a hard error), while parseUiLocale and parseLoginHint fall
 * back to safe defaults (Keycloak's lenient handling).
 */
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
    public static function validateRedirectUri(Client $client, string $redirectUri): void
    {
        if (!self::uriMatches($client->getUri(), $redirectUri)) {
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

        return str_ends_with($registered, '*')
            && self::originOf($registered) === self::originOf($requested)
            && self::pathMatches($registered, $requested);
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

        if (!str_starts_with($requestedPath, $prefix)) {
            return false;
        }
        $rest = substr($requestedPath, strlen($prefix));
        return $prefix === '/' || str_ends_with($prefix, '/') || $rest === '' || $rest[0] === '/' || $rest[0] === '?';
    }

    public static function validateQueryParams(array $query): void
    {
        $requiredFields = [
            'scope',
            'client_id',
            'response_type',
            'redirect_uri',
        ];

        $codeChallengeMethod = $query['code_challenge_method'] ?? null;
        if ($codeChallengeMethod !== null) {
            if ($codeChallengeMethod !== 'S256') {
                throw new ValidationFailed('unsupported code challenge method');
            }
            $requiredFields[] = 'code_challenge';
        }

        self::validateParams($query, $requiredFields);

        if (($query['response_type'] ?? '') !== 'code') {
            throw OAuth2Error::unsupportedResponseType('unsupported response_type');
        }

        $responseMode = $query['response_mode'] ?? 'query';
        if (!in_array($responseMode, ['fragment', 'query'])) {
            throw new ValidationFailed('invalid response mode');
        }

        if (!in_array('openid', explode(' ', $query['scope']))) {
            throw OAuth2Error::invalidScope('invalid scope');
        }
    }

    public static function validateTokenParams(array $query): void
    {
        $requiredFields = [
            'grant_type',
            'client_id',
        ];

        self::validateParams($query, $requiredFields);

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

    /**
     * OIDC Core §3.1.2.1 `max_age`: max seconds since authentication.
     * Returns null when absent; throws on malformed values.
     *
     * Digits beyond a native int saturate to PHP_INT_MAX (effectively "no
     * limit"); 0 forces re-authentication unless the session was created in
     * the same second.
     *
     * @param mixed $value raw query value
     */
    public static function parseMaxAge(mixed $value): int|null
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_int($value) && $value >= 0) {
            return $value;
        }
        if (is_string($value) && ctype_digit($value)) {
            return (int) $value;
        }
        throw new ValidationFailed('invalid max_age');
    }

    /**
     * OIDC Core §3.1.2.1 `ui_locales`: space-separated BCP47 tags.
     * Returns the first well-formed tag for the login page `lang`
     * attribute, defaulting to `en`. Never throws: an unusable value
     * simply falls back, matching Keycloak's lenient handling.
     *
     * @param mixed $value raw query value
     */
    public static function parseUiLocale(mixed $value): string
    {
        if (!is_string($value)) {
            return 'en';
        }
        $tokens = preg_split('/\s+/', trim($value));
        if ($tokens === false) {
            return 'en';
        }

        return self::firstValidLocale($tokens);
    }

    /**
     * @param list<string> $tokens
     */
    private static function firstValidLocale(array $tokens): string
    {
        foreach ($tokens as $token) {
            if (preg_match('/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/', $token) === 1) {
                return $token;
            }
        }

        return 'en';
    }

    /**
     * OIDC Core §3.1.2.1 `login_hint`: opportunistic username hint.
     * Returns the raw hint for pre-filling the login form, or an empty
     * string when absent or malformed (never throws).
     *
     * @param mixed $value raw query value
     */
    public static function parseLoginHint(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }
        $hint = trim($value);
        if ($hint === '') {
            return '';
        }
        return mb_substr($hint, 0, 320);
    }

    public static function validateCodeChallenge(?string $codeChallenge, ?string $codeVerifier): void
    {
        if ($codeVerifier === null) {
            throw OAuth2Error::invalidGrant('invalid code_verifier');
        }
        if ($codeChallenge !== Base64Utils::b64UrlEncode(hash('sha256', $codeVerifier, true))) {
            throw OAuth2Error::invalidGrant('code_verifier does not match code_challenge');
        }
    }

    private static function validateParams(array $params, array $requiredFields): void
    {
        $missing = [];

        foreach ($requiredFields as $f) {
            if (!isset($params[$f]) || $params[$f] === ' ') {
                $missing[] = $f;
            }
        }

        if (!empty($missing)) {
            $missingStr = implode(', ', $missing);
            $s = count($missing) > 1 ? 's' : '';
            throw new ValidationFailed("missing required parameter$s ($missingStr)");
        }
    }
}
