<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\PasswordPolicy;
use PHPUnit\Framework\TestCase;

class PasswordPolicyTest extends TestCase
{
    public function testEmptyPolicyIsAllInherit(): void
    {
        $policy = new PasswordPolicy();

        self::assertSame(
            ['min_length' => null, 'min_lower' => null, 'min_upper' => null, 'min_digits' => null, 'min_special' => null],
            $policy->toArray()
        );
    }

    public function testFromConfigArrayFallsBackToDocumentedDefaults(): void
    {
        $policy = PasswordPolicy::fromConfigArray([]);

        self::assertSame(8, $policy->minLength);
        self::assertSame(0, $policy->minLower);
        self::assertSame(0, $policy->minUpper);
        self::assertSame(1, $policy->minDigits);
        self::assertSame(1, $policy->minSpecial);
    }

    public function testFromConfigArrayParsesIniStrings(): void
    {
        $policy = PasswordPolicy::fromConfigArray([
            'min_length' => '12',
            'min_lower' => '1',
            'min_upper' => '1',
            'min_digits' => '2',
            'min_special' => '0',
        ]);

        self::assertSame(12, $policy->minLength);
        self::assertSame(2, $policy->minDigits);
        self::assertSame(0, $policy->minSpecial);
    }

    public function testFromConfigArrayFallsBackToDefaultsOnGarbage(): void
    {
        $policy = PasswordPolicy::fromConfigArray([
            'min_length' => 'lots',
            'min_special' => '1.5',
        ]);

        self::assertSame(PasswordPolicy::DEFAULT_MIN_LENGTH, $policy->minLength);
        self::assertSame(PasswordPolicy::DEFAULT_MIN_SPECIAL, $policy->minSpecial);
    }

    public function testFromConfigArrayRejectsNegativeValues(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('min_digits');

        PasswordPolicy::fromConfigArray(['min_digits' => '-3']);
    }

    public function testFromRowClampsNegativeDbValues(): void
    {
        $policy = PasswordPolicy::fromRow(['password_min_digits' => -3]);

        self::assertSame(0, $policy->minDigits);
    }

    public function testFromRowKeepsNullsAndCasts(): void
    {
        $policy = PasswordPolicy::fromRow([
            'password_min_length' => 10,
            'password_min_digits' => '2',
        ]);

        self::assertSame(10, $policy->minLength);
        self::assertSame(2, $policy->minDigits);
        self::assertNull($policy->minLower);
        self::assertNull($policy->minUpper);
        self::assertNull($policy->minSpecial);
    }

    public function testWithFallbackResolvesNullsPerField(): void
    {
        $realm = new PasswordPolicy(minLength: 12, minDigits: 0);
        $global = PasswordPolicy::fromConfigArray([]);

        $effective = $realm->withFallback($global);

        self::assertSame(12, $effective->minLength);
        self::assertSame(0, $effective->minLower);
        self::assertSame(0, $effective->minDigits);
        self::assertSame(1, $effective->minSpecial);
    }
}
