<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum LoginStatus: string
{
    case Pending = 'PENDING';
    case Authenticated = 'AUTHENTICATED';
    case Active = 'ACTIVE';
    case Expired = 'EXPIRED';
}
