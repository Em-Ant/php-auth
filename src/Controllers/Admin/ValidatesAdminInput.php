<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;

trait ValidatesAdminInput
{
    private function requiredString(array $body, string $field): string
    {
        $value = $body[$field] ?? '';
        if (!is_string($value) || trim($value) === '') {
            throw new ValidationFailed("missing required field '$field'");
        }
        return trim($value);
    }

    private function optionalString(array $body, string $field, ?string $default): ?string
    {
        if (!array_key_exists($field, $body) || $body[$field] === null) {
            return $default;
        }
        return $this->requiredString($body, $field);
    }

    private function optionalBool(array $body, string $field, bool $default): bool
    {
        if (!array_key_exists($field, $body) || $body[$field] === null) {
            return $default;
        }
        return filter_var($body[$field], FILTER_VALIDATE_BOOLEAN);
    }

    private function optionalInt(array $body, string $field, int $default): int
    {
        if (!array_key_exists($field, $body) || $body[$field] === null) {
            return $default;
        }
        $value = $body[$field];
        if (!is_int($value) || $value < 1) {
            throw new ValidationFailed("'$field' must be a positive integer");
        }
        return $value;
    }

    private function queryString(array $query, string $key): ?string
    {
        $value = $query[$key] ?? null;
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        return trim($value);
    }

    private function queryInt(array $query, string $key, int $default, int $min, ?int $max): int
    {
        $raw = $query[$key] ?? null;
        if ($raw === null || $raw === '') {
            return $default;
        }

        $value = filter_var($raw, FILTER_VALIDATE_INT);
        if ($value === false || $value < $min || ($max !== null && $value > $max)) {
            return $default;
        }

        return $value;
    }
}
