<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Models\KeySet;

class FilesystemKeyStore implements KeyStore
{
    public function __construct(
        private readonly string $keysDir,
    ) {
    }

    public function findKeys(string $kid): KeySet
    {
        $dir = "{$this->keysDir}/$kid";

        $publicKey = $this->loadFile("$dir/public_key.pem");
        $privateKey = $this->loadFile("$dir/private_key.pem");
        $cert = $this->loadFile("$dir/cert.pem");

        $jwksJson = $this->loadFile("$dir/keys.json");
        $jwks = json_decode($jwksJson, true);

        return new KeySet($publicKey, $privateKey, $cert, $jwks);
    }

    private function loadFile(string $path): string
    {
        $content = @file_get_contents($path);

        if ($content === false) {
            throw new \RuntimeException("File not found: $path");
        }

        return $content;
    }
}
