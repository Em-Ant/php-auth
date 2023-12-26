<?php

declare(strict_types=1);

namespace AuthServer\Ports\In\Shared;

class InvalidInputException extends \UnexpectedValueException
{
    public function __construct(string $message)
    {
        parent::__construct($message, 400);
    }
}
