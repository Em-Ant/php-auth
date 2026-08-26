<?php

declare(strict_types=1);

namespace AuthServer\Services;

final class ClientCredentials
{
    /**
     * Merges client credentials from an `Authorization: Basic` header into
     * the request body. Explicit body parameters win over the header.
     */
    public static function mergeFromBasicHeader(array $body, string $authHeader): array
    {
        if (!str_starts_with($authHeader, 'Basic ')) {
            return $body;
        }

        $cred = explode(':', base64_decode(substr($authHeader, 6)), 2);
        if (!isset($body['client_id'])) {
            $body['client_id'] = $cred[0];
        }
        if (!isset($body['client_secret'])) {
            $body['client_secret'] = $cred[1] ?? null;
        }

        return $body;
    }
}
