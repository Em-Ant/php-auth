<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum SessionStatus: string
{
    case Active = 'ACTIVE';
    case Expired = 'EXPIRED';
}
