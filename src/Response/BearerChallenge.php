<?php

declare(strict_types=1);

namespace AuthServer\Response;

/**
 * RFC 6750 §3 Bearer challenge value for the WWW-Authenticate header on
 * 401 responses. Shared by the resource-server and admin middlewares so
 * the challenge format and its header hardening live in one place.
 */
final class BearerChallenge
{
    public static function create(string $realm, string $description): string
    {
        return sprintf(
            'Bearer realm="%s", error="invalid_token", error_description="%s"',
            self::sanitize($realm),
            self::sanitize($description)
        );
    }

    /**
     * Both values are embedded inside quoted-strings: a `"` would break
     * out of the quoted-string and CR/LF would split the header
     * (response splitting). Stripping them keeps the challenge well-formed.
     */
    private static function sanitize(string $value): string
    {
        return str_replace(['"', "\r", "\n"], '', $value);
    }
}
