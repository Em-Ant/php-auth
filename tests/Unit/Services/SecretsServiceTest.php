<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\SecretsService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class SecretsServiceTest extends TestCase
{
    public function testGenerateCodeReturnsThreePartsSeparatedByDot(): void
    {
        $s = new SecretsService();
        $code = $s->generateCode();
        $parts = explode('.', $code);
        self::assertCount(3, $parts);
    }

    public function testGenerateCodeEachPartIsUuid(): void
    {
        $s = new SecretsService();
        $code = $s->generateCode();
        $parts = explode('.', $code);
        foreach ($parts as $part) {
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
                $part
            );
        }
    }

    public function testGenerateCodeIsUnique(): void
    {
        $s = new SecretsService();
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = $s->generateCode();
        }
        self::assertCount(10, array_unique($codes));
    }

    #[DataProvider('hashAlgorithmsProvider')]
    public function testHashAndVerifyRoundtrip(?array $config): void
    {
        $s = new SecretsService($config);
        $plain = 'my-secret-password';
        $hash = $s->hashPassword($plain);
        self::assertTrue($s->validatePassword($plain, $hash));
        self::assertFalse($s->validatePassword('wrong', $hash));
    }

    public static function hashAlgorithmsProvider(): array
    {
        return [
            'default (argon2id)' => [null],
            'argon2id explicit' => [[
                'algorithm' => 'argon2id',
                'argon2_memory_cost' => 512,
                'argon2_time_cost' => 1,
                'argon2_threads' => 1,
            ]],
            'bcrypt' => [[
                'algorithm' => 'bcrypt',
                'bcrypt_cost' => 4,
            ]],
        ];
    }

    #[DataProvider('hashAlgorithmInfoProvider')]
    public function testHashUsesExpectedAlgorithm(?array $config, string $expectedAlgo): void
    {
        $s = new SecretsService($config);
        $hash = $s->hashPassword('tst');
        $info = password_get_info($hash);
        self::assertSame($expectedAlgo, $info['algoName']);
    }

    public static function hashAlgorithmInfoProvider(): array
    {
        return [
            'default' => [null, 'argon2id'],
            'argon2id' => [['algorithm' => 'argon2id'], 'argon2id'],
            'bcrypt' => [['algorithm' => 'bcrypt'], 'bcrypt'],
        ];
    }
}
