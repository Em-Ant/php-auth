<?php

declare(strict_types=1);

namespace AuthServer\Services;

use Psr\Http\Message\ResponseInterface;
use Slim\Views\PhpRenderer;

class ViewRenderer
{
    private PhpRenderer $renderer;

    public function __construct(string $viewsPath, string $layoutPath)
    {
        $this->renderer = new PhpRenderer(
            $viewsPath,
            ['sub_path' => $GLOBALS['sub_path'] ?? ''],
            $layoutPath
        );
    }

    public function render(
        ResponseInterface $response,
        string $template,
        array $params = []
    ): ResponseInterface {
        $response = $response->withHeader('Content-Type', 'text/html; charset=utf-8');
        return $this->renderer->render($response, $template, $params);
    }
}
