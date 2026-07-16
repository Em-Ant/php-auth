<?php

declare(strict_types=1);

namespace AuthServer\Services;

readonly class Migration
{
    public function __construct(
        public int $version,
        public string $name,
        public string $upFile,
        public ?string $downFile = null,
    ) {
    }
}
