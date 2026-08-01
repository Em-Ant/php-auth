<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\RedirectUri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RedirectUriTest extends TestCase
{
    public function testQueryModeAppendsWithQuestionMark(): void
    {
        $uri = new RedirectUri('http://example.com/cb', 'query', ['code' => 'abc', 'state' => 'xyz']);
        self::assertSame('http://example.com/cb?code=abc&state=xyz', (string) $uri);
    }

    public function testQueryModeWithExistingQueryAppendsAmpersand(): void
    {
        $uri = new RedirectUri('http://example.com/cb?existing=1', 'query', ['code' => 'abc']);
        self::assertSame('http://example.com/cb?existing=1&code=abc', (string) $uri);
    }

    public function testQueryModeWithFragmentMovesFragmentAfterQuery(): void
    {
        $uri = new RedirectUri('http://example.com/cb#frag', 'query', ['code' => 'abc']);
        self::assertSame('http://example.com/cb?code=abc#frag', (string) $uri);
    }

    public function testFragmentModeAppendsWithHash(): void
    {
        $uri = new RedirectUri('http://example.com/cb', 'fragment', ['code' => 'abc', 'state' => 'xyz']);
        self::assertSame('http://example.com/cb#code=abc&state=xyz', (string) $uri);
    }

    public function testFragmentModeWithExistingFragmentAppendsAmpersand(): void
    {
        $uri = new RedirectUri('http://example.com/cb#existing', 'fragment', ['code' => 'abc']);
        self::assertSame('http://example.com/cb#existing&code=abc', (string) $uri);
    }

    public function testEmptyParamsReturnsBaseUri(): void
    {
        $uri = new RedirectUri('http://example.com/cb', 'query', []);
        self::assertSame('http://example.com/cb?', (string) $uri);
    }

    public function testInvalidResponseModeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $uri = new RedirectUri('http://example.com/cb', 'invalid', ['code' => 'abc']);
        self::assertInstanceOf(RedirectUri::class, $uri);
    }

    #[DataProvider('specialCharsProvider')]
    public function testSpecialCharactersAreEncoded(string $input, string $expected): void
    {
        $uri = new RedirectUri('http://example.com/cb', 'query', ['val' => $input]);
        self::assertStringContainsString($expected, (string) $uri);
    }

    public static function specialCharsProvider(): array
    {
        return [
            'space' => ['a b', 'val=a+b'],
            'plus'  => ['a+b', 'val=a%2Bb'],
            'slash' => ['a/b', 'val=a%2Fb'],
            'unicode' => ['è', 'val=%C3%A8'],
        ];
    }
}
