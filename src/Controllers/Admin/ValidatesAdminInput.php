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

    /**
     * Boolean body field: absent or null yields the default. Accepts JSON
     * booleans plus their 1/0/"true"/"false" spellings; anything else is a
     * 400 — a coerced wrong value must never be mistaken for a decision.
     */
    private function strictBool(array $body, string $field, bool $default): bool
    {
        $value = array_key_exists($field, $body) ? $body[$field] : null;
        if ($value === null) {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }

        return match ($value) {
            1, '1', 'true' => true,
            0, '0', 'false' => false,
            default => throw new ValidationFailed("'$field' must be a boolean (true/false/1/0)"),
        };
    }

    private function optionalInt(array $body, string $field, int $default): int
    {
        [$present, $value] = $this->submittedValue($body, $field);
        if (!$present) {
            return $default;
        }
        if (!is_int($value) || $value < 1) {
            throw new ValidationFailed("'$field' must be a positive integer");
        }
        return $value;
    }

    /**
     * Nullable non-negative body field for per-realm password-policy rules:
     * absent or null yields the default (null = inherit the global default),
     * an explicit 0 disables the rule. Anything else is a 400.
     */
    private function optionalPolicyInt(array $body, string $field, int|null $default): int|null
    {
        [$present, $value] = $this->submittedValue($body, $field);
        if (!$present) {
            return $default;
        }
        if (!is_int($value) || $value < 0) {
            throw new ValidationFailed("'$field' must be a non-negative integer or null");
        }
        return $value;
    }

    /**
     * Splits "not submitted" (absent or null → caller default) from
     * "submitted" (raw value for the caller to validate). Both integer
     * flavors share it so they cannot disagree on what counts as absent.
     *
     * @return array{0: bool, 1: mixed}
     */
    private function submittedValue(array $body, string $field): array
    {
        if (!array_key_exists($field, $body) || $body[$field] === null) {
            return [false, null];
        }

        return [true, $body[$field]];
    }

    /**
     * @return array{limit: int, offset: int}
     */
    private function paginationFromQuery(array $query): array
    {
        return [
            'limit' => $this->queryInt($query, 'limit', 50, 1, 200),
            'offset' => $this->queryInt($query, 'offset', 0, 0, null),
        ];
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
