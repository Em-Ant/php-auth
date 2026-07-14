<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Response;

use AuthServer\Response\JsonResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class JsonResponseTest extends TestCase
{
    private ResponseInterface $response;
    private StreamInterface $stream;

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
    }

    public function testCreateSetsJsonContentType(): void
    {
        $this->response->method('getBody')->willReturn($this->stream);
        $this->stream->expects(self::once())->method('write');
        $this->response->expects(self::once())
            ->method('withHeader')
            ->with('Content-Type', 'application/json')
            ->willReturn($this->response);
        $this->response->method('withStatus')->willReturn($this->response);

        JsonResponse::create($this->response, ['key' => 'val']);
    }

    public function testCreateSetsStatusCode(): void
    {
        $this->response->method('getBody')->willReturn($this->stream);
        $this->stream->method('write');
        $this->response->method('withHeader')->willReturn($this->response);
        $this->response->expects(self::once())
            ->method('withStatus')
            ->with(201)
            ->willReturn($this->response);

        JsonResponse::create($this->response, ['key' => 'val'], 201);
    }

    public function testCreateSetsOriginHeader(): void
    {
        $this->response->method('getBody')->willReturn($this->stream);
        $this->stream->method('write');

        $callCount = 0;
        $this->response->method('withHeader')->willReturnCallback(
            function (string $name, string $value) use (&$callCount) {
                $callCount++;
                if ($callCount === 1) {
                    self::assertSame('Content-Type', $name);
                }
                if ($callCount === 2) {
                    self::assertSame('Access-Control-Allow-Origin', $name);
                    self::assertSame('https://example.com', $value);
                }
                return $this->response;
            }
        );
        $this->response->method('withStatus')->willReturn($this->response);

        JsonResponse::create($this->response, [], 200, 'https://example.com');
    }

    public function testErrorReturnsErrorStructure(): void
    {
        $this->response->method('getBody')->willReturn($this->stream);
        $this->stream->expects(self::once())->method('write')
            ->with(self::callback(function (string $json) {
                $data = json_decode($json, true);
                return isset($data['error'])
                    && isset($data['error_description'])
                    && $data['error'] === 'invalid_request'
                    && $data['error_description'] === 'Missing parameter';
            }));
        $this->response->method('withHeader')->willReturn($this->response);
        $this->response->expects(self::once())
            ->method('withStatus')
            ->with(400)
            ->willReturn($this->response);

        JsonResponse::error($this->response, 'invalid_request', 'Missing parameter');
    }
}
