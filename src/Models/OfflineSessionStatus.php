<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum OfflineSessionStatus: string
{
    case Active = 'ACTIVE';
    case Expired = 'EXPIRED';
}
