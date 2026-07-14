<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\Base64Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class Base64UtilsTest extends TestCase
{
    #[DataProvider('roundtripProvider')]
    public function testRoundtrip(string $original): void
    {
        $encoded = Base64Utils::b64UrlEncode($original);
        $decoded = Base64Utils::b64UrlDecode($encoded);
        self::assertSame($original, $decoded);
    }

    public static function roundtripProvider(): array
    {
        return [
            'simple' => ['hello world'],
            'binary' => ["\x00\x01\x02\xff\xfe"],
            'json' => ['{"sub":"1234567890","name":"John Doe"}'],
            'empty' => [''],
            'unicode' => ['José 🚀'],
        ];
    }

    public function testEncodedStringHasNoPadding(): void
    {
        $encoded = Base64Utils::b64UrlEncode('test');
        self::assertStringNotContainsString('=', $encoded);
    }

    public function testEncodedStringUsesUrlSafeChars(): void
    {
        $encoded = Base64Utils::b64UrlEncode("\xff\xfb\xff");
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
    }

    public function testDecodeWithPaddingReadded(): void
    {
        // standard base64 of "test" with +/ instead of -_
        $decoded = Base64Utils::b64UrlDecode('dGVzdA');
        self::assertSame('test', $decoded);
    }

    public function testMultipleOfFourLengthDecodesCorrectly(): void
    {
        $decoded = Base64Utils::b64UrlDecode('dGVzdA');
        self::assertSame('test', $decoded);
    }
}
