<?php

declare(strict_types=1);

namespace AuthServer\Services;

class Base64Utils
{
    public static function b64UrlEncode(string $data): string
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($data)
        );
    }

    public static function b64UrlDecode(string $data): string
    {
        $b64 = str_replace(['-', '_'], ['+', '/'], $data);

        while (strlen($b64) % 4 != 0) {
            $b64 = $b64 . '=';
        }

        return base64_decode($b64);
    }
}
