<?php

declare(strict_types=1);

namespace AuthServer\Core\Ports\In\LoginRequest;


interface LoginRequestHandlerInterface
{
    public function handleLoginRequest(LoginRequestInput $input): void;
}
