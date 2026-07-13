<?php

declare(strict_types=1);

namespace AuthServer\Response;

use Psr\Http\Message\ResponseInterface;

class JsonResponse
{
    public static function create(
        ResponseInterface $response,
        mixed $data,
        int $status = 200,
        ?string $origin = null
    ): ResponseInterface {
        $response->getBody()->write(
            json_encode($data, JSON_UNESCAPED_SLASHES)
        );

        $response = $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($status);

        if ($origin !== null) {
            $response = $response->withHeader(
                'Access-Control-Allow-Origin',
                $origin
            );
        }

        return $response;
    }

    public static function error(
        ResponseInterface $response,
        string $error,
        string $description,
        int $status = 400,
        ?string $origin = null
    ): ResponseInterface {
        return self::create(
            $response,
            [
                'error' => $error,
                'error_description' => $description,
            ],
            $status,
            $origin
        );
    }
}
