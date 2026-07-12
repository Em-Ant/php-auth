<?php

declare(strict_types=1);

namespace AuthServer\Models;

class KeySet
{
    public function __construct(
        public readonly string $publicKey,
        public readonly string $privateKey,
        public readonly string $cert,
        public readonly array $jwks,
    ) {
    }
}
