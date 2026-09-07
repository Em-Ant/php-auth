<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\PasswordPolicy;

/**
 * Pure password-policy check: a candidate against an effective policy.
 * Null rules count as disabled; callers resolve realm inheritance first via
 * PasswordPolicy::withFallback(). All violations are reported at once so a
 * single 400 tells the user everything to fix.
 */
final class PasswordPolicyValidator
{
    /**
     * @throws ValidationFailed listing every violated rule.
     */
    public function validate(string $password, PasswordPolicy $policy): void
    {
        $violations = [];

        if (strlen($password) < ($policy->minLength ?? 0)) {
            $violations[] = "password must be at least {$policy->minLength} characters";
        }

        $counts = self::countClasses($password);
        $requirements = [
            ['lowercase letter', $policy->minLower ?? 0, $counts['lower']],
            ['uppercase letter', $policy->minUpper ?? 0, $counts['upper']],
            ['digit', $policy->minDigits ?? 0, $counts['digit']],
            ['special character', $policy->minSpecial ?? 0, $counts['special']],
        ];
        foreach ($requirements as [$label, $required, $found]) {
            if ($found < $required) {
                $violations[] = "password must contain at least $required $label"
                    . ($required === 1 ? '' : 's');
            }
        }

        if ($violations !== []) {
            throw new ValidationFailed(implode('; ', $violations));
        }
    }

    /**
     * @return array{lower: int, upper: int, digit: int, special: int}
     */
    private static function countClasses(string $password): array
    {
        return [
            'lower' => self::countMatches('/[a-z]/', $password),
            'upper' => self::countMatches('/[A-Z]/', $password),
            'digit' => self::countMatches('/[0-9]/', $password),
            'special' => self::countMatches('/[^a-zA-Z0-9]/', $password),
        ];
    }

    private static function countMatches(string $pattern, string $subject): int
    {
        $count = preg_match_all($pattern, $subject);

        return $count === false ? 0 : $count;
    }
}
