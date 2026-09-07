<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * Password rules for a realm. Every field is nullable: null means "inherit"
 * (a realm policy resolves each null against the global defaults via
 * withFallback()); 0 disables that rule. Character classes are ASCII.
 */
final class PasswordPolicy implements \JsonSerializable
{
    public const DEFAULT_MIN_LENGTH = 8;
    public const DEFAULT_MIN_LOWER = 0;
    public const DEFAULT_MIN_UPPER = 0;
    public const DEFAULT_MIN_DIGITS = 1;
    public const DEFAULT_MIN_SPECIAL = 1;

    public function __construct(
        public readonly int|null $minLength = null,
        public readonly int|null $minLower = null,
        public readonly int|null $minUpper = null,
        public readonly int|null $minDigits = null,
        public readonly int|null $minSpecial = null,
    ) {
    }

    /**
     * Builds the global policy from the `[password_policy]` config section.
     * Missing or non-numeric keys fall back to the documented defaults;
     * negatives are clamped to 0 (a negative rule is meaningless).
     */
    public static function fromConfigArray(array $config): self
    {
        return new self(
            self::configInt($config, 'min_length', self::DEFAULT_MIN_LENGTH),
            self::configInt($config, 'min_lower', self::DEFAULT_MIN_LOWER),
            self::configInt($config, 'min_upper', self::DEFAULT_MIN_UPPER),
            self::configInt($config, 'min_digits', self::DEFAULT_MIN_DIGITS),
            self::configInt($config, 'min_special', self::DEFAULT_MIN_SPECIAL),
        );
    }

    /**
     * Builds a realm policy from a DB row. Missing or null columns stay
     * null (inherit); this also tolerates rows read from a pre-010 schema.
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::rowInt($row, 'password_min_length'),
            self::rowInt($row, 'password_min_lower'),
            self::rowInt($row, 'password_min_upper'),
            self::rowInt($row, 'password_min_digits'),
            self::rowInt($row, 'password_min_special'),
        );
    }

    /**
     * Resolves inheritance: each null field takes the fallback's value.
     * Resolving a realm policy against the global policy always yields a
     * complete (non-null) policy.
     */
    public function withFallback(self $fallback): self
    {
        return new self(
            $this->minLength ?? $fallback->minLength,
            $this->minLower ?? $fallback->minLower,
            $this->minUpper ?? $fallback->minUpper,
            $this->minDigits ?? $fallback->minDigits,
            $this->minSpecial ?? $fallback->minSpecial,
        );
    }

    /**
     * @return array{
     *     min_length: int|null,
     *     min_lower: int|null,
     *     min_upper: int|null,
     *     min_digits: int|null,
     *     min_special: int|null,
     * }
     */
    public function toArray(): array
    {
        return [
            'min_length' => $this->minLength,
            'min_lower' => $this->minLower,
            'min_upper' => $this->minUpper,
            'min_digits' => $this->minDigits,
            'min_special' => $this->minSpecial,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    private static function configInt(array $config, string $key, int $default): int
    {
        return self::parseRuleValue($config[$key] ?? null) ?? $default;
    }

    private static function rowInt(array $row, string $key): int|null
    {
        return self::parseRuleValue($row[$key] ?? null);
    }

    /**
     * Parses one rule value: integers and numeric strings are accepted and
     * clamped to 0, anything else (null, missing, garbage) is null so the
     * caller decides between inheriting and falling back to a default.
     */
    private static function parseRuleValue(mixed $raw): int|null
    {
        if (is_int($raw)) {
            return max(0, $raw);
        }
        if (is_string($raw) && filter_var($raw, FILTER_VALIDATE_INT) !== false) {
            return max(0, (int) $raw);
        }

        return null;
    }
}
