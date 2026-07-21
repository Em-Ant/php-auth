<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Services\ViewRenderer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ErrorController
{
    private ViewRenderer $view;

    public function __construct(ViewRenderer $view)
    {
        $this->view = $view;
    }

    public function error(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $message = $query['e'] ?? '';

        return $this->view->render($response, 'error.php', [
            'title' => 'Error',
            'error' => $message,
        ]);
    }
}
