<?php

declare(strict_types=1);

namespace AuthServer\Core\Ports\In\LoginRequest;

enum CodeChallengeMethod: string
{
    case S256 = 'S256';
    case Plain = 'plain';
}
