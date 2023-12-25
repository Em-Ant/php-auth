<?php

namespace AuthServer\Interfaces;

interface Logger
{
    public function debug(string $message, ?string $name = ''): void;
    public function info(string $message, ?string $name = ''): void;
    public function warning(string $message, ?string $name = ''): void;
    public function error(string $message, ?string $name = ''): void;
    public function clear_log(): void;
}
