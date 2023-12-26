<?php

declare(strict_types=1);

namespace AuthServer\Core\Ports\In\LoginRequest;

enum Prompt: string
{
    case None = 'none';
    case Login = 'login';
}
