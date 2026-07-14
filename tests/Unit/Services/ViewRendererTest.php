<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\ViewRenderer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class ViewRendererTest extends TestCase
{
    public function testRenderSetsContentTypeAndReturnsResponse(): void
    {
        $GLOBALS['sub_path'] = '';

        $renderer = new ViewRenderer(
            __DIR__ . '/../../../src/views',
            'template.php',
        );

        $stream = $this->createMock(StreamInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturn($response);

        $result = $renderer->render($response, 'login_form.php', [
            'title' => 'Login',
            'login_id' => 'test-id',
            'csrf_token' => 'test-token',
            'realm' => 'test',
            'email' => '',
            'password' => '',
            'error' => false,
        ]);

        self::assertSame($response, $result);
    }
}
