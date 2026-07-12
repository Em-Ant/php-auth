<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Login;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\Realm;

interface LoginStateMachine
{
    /**
     * @param array<string, mixed> $context
     */
    public function transition(Login $login, LoginEvent $event, Realm $realm, array $context = []): Login;
}
