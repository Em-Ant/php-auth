<?php

declare(strict_types=1);

namespace AuthServer\Exceptions;

class BadRequestException extends \UnexpectedValueException
{
    public function __construct(string $message)
    {
        parent::__construct($message, 400);
    }
}
