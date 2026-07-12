<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum LoginEvent: string
{
    case Authenticate = 'authenticate';
    case Activate = 'activate';
    case Refresh = 'refresh';
    case Expire = 'expire';
    case CheckExpiry = 'check_expiry';
}
