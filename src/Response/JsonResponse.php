<?php

declare(strict_types=1);

namespace AuthServer\Response;

use AuthServer\Exceptions\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Throwable;

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
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
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

    public static function paginated(
        ResponseInterface $response,
        array $items,
        int $total,
        int $limit,
        int $offset
    ): ResponseInterface {
        return self::create($response, [
            'items' => $items,
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset,
        ]);
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

    public static function invalidRequest(
        ResponseInterface $response,
        Throwable $e
    ): ResponseInterface {
        return self::error($response, 'invalid_request', $e->getMessage(), 400);
    }

    public static function errorFromOAuth2Error(
        ResponseInterface $response,
        OAuth2Error $error
    ): ResponseInterface {
        return self::error(
            $response,
            $error->getError(),
            $error->getMessage(),
            $error->getStatus()
        );
    }
}
