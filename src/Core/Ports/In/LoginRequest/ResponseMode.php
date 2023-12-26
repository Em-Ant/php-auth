<?php

declare(strict_types=1);

namespace AuthServer\Core\Ports\In\LoginRequest;

enum ResponseMode: string
{
    case Fragment = 'fragment';
    case Query = 'query';
}
