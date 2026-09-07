<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\PasswordPolicy;
use AuthServer\Services\PasswordPolicyValidator;
use PHPUnit\Framework\TestCase;

class PasswordPolicyValidatorTest extends TestCase
{
    private PasswordPolicyValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new PasswordPolicyValidator();
    }

    public function testCompliantPasswordPasses(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('Secret123!', new PasswordPolicy(8, 1, 1, 1, 1));
    }

    public function testShortPasswordReportsLength(): void
    {
        try {
            $this->validator->validate('S1!', new PasswordPolicy(8, 0, 0, 0, 0));
            self::fail('expected ValidationFailed');
        } catch (ValidationFailed $e) {
            self::assertStringContainsString('at least 8 characters', $e->getMessage());
        }
    }

    public function testMissingClassesAreEachReported(): void
    {
        try {
            $this->validator->validate('abcdefgh', new PasswordPolicy(8, 0, 0, 1, 1));
            self::fail('expected ValidationFailed');
        } catch (ValidationFailed $e) {
            self::assertStringContainsString('at least 1 digit', $e->getMessage());
            self::assertStringContainsString('at least 1 special character', $e->getMessage());
            self::assertStringNotContainsString('characters', $e->getMessage());
        }
    }

    public function testPluralLabelsForCountsAboveOne(): void
    {
        try {
            $this->validator->validate('abcdefG1!', new PasswordPolicy(8, 0, 2, 2, 2));
            self::fail('expected ValidationFailed');
        } catch (ValidationFailed $e) {
            self::assertStringContainsString('at least 2 uppercase letters', $e->getMessage());
            self::assertStringContainsString('at least 2 digits', $e->getMessage());
            self::assertStringContainsString('at least 2 special characters', $e->getMessage());
        }
    }

    public function testNullRulesAreDisabled(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('x', new PasswordPolicy());
    }

    public function testExplicitZeroDisablesARule(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('nodigitshere!', new PasswordPolicy(8, 0, 0, 0, 1));
    }
}
