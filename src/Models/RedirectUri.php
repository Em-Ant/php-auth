<?php

declare(strict_types=1);

namespace AuthServer\Models;

class RedirectUri
{
    private string $uri;

    public function __construct(
        string $baseUri,
        string $responseMode,
        array $params
    ) {
        if (!in_array($responseMode, ['fragment', 'query'], true)) {
            throw new \InvalidArgumentException(
                'response_mode must be "fragment" or "query"'
            );
        }

        $uri = $baseUri;
        $append = '';
        $hashPos = strpos($uri, '#');

        if ($responseMode === 'query') {
            $char = strpos($uri, '?') !== false ? '&' : '?';
            if ($hashPos !== false) {
                $append = substr($uri, $hashPos);
                $uri = substr($uri, 0, $hashPos);
            }
        } else {
            $char = $hashPos !== false ? '&' : '#';
        }

        $queryString = http_build_query($params);

        $this->uri = $uri . $char . $queryString . $append;
    }

    public function __toString(): string
    {
        return $this->uri;
    }
}
