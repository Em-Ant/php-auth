<?php

declare(strict_types=1);

namespace AuthServer;

use DateTime;
use DateTimeInterface;
use DateTimeZone;

const SQL_DATETIME_FORMAT = 'Y-m-d H:i:s';

function getGuid(): string
{
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function sql_now(): string
{
    return gmdate(SQL_DATETIME_FORMAT);
}

function format_sql_datetime(?DateTimeInterface $datetime): ?string
{
    return $datetime?->format(SQL_DATETIME_FORMAT);
}

function parse_sql_datetime(?string $value): ?DateTime
{
    if ($value === null) {
        return null;
    }

    $parsed = DateTime::createFromFormat(SQL_DATETIME_FORMAT, $value, new DateTimeZone('UTC'));
    return $parsed ?: null;
}
