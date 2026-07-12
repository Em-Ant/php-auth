<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\KeySet;

interface KeyStore
{
    public function findKeys(string $kid): KeySet;
}
