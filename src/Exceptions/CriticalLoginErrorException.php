<?php

declare(strict_types=1);

namespace AuthServer\Exceptions;

class CriticalLoginErrorException extends \Exception
{
    public function __construct(string $message)
    {
        parent::__construct($message, 400);
    }
}
