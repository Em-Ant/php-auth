<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case RefreshToken = 'refresh_token';
    case ClientCredentials = 'client_credentials';
}
