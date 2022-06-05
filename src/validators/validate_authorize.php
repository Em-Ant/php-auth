<?php

namespace AuthServer\Validators;

use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Models\Client;

require_once 'src/interfaces/client_repository.php';
require_once 'src/exceptions/invalid_input_exception.php';


class ValidateAuthorize
{
    private IClientRepo $client_repository;

    public function __construct(IClientRepo $repo)
    {
        $this->client_repository = $repo;
    }

    public function execute(array $query)
    {
        self::validate_query_params($query);
        $client = $this->get_client($query['client_id']);
        self::validate_redirect_uri($client, $query['redirect_uri']);
    }

    private function get_client(string $client_id): Client
    {
        $client = $this->client_repository->findClientByClientId($client_id);
        if ($client === null) {
            throw new InvalidInputException('invalid client id');
        }
        return $client;
    }
    private static function validate_redirect_uri(Client $client, string $redirect_uri)
    {
        $_redirect_uri = rtrim($redirect_uri, '/');
        $_client_uri = rtrim($client->get_uri(), '/');

        if ($_redirect_uri !== $_client_uri &&
          !self::str_starts_with($_redirect_uri, $_client_uri.'/')
      ) {
            throw new InvalidInputException('invalid redirect_uri');
        }
    }
    private static function str_starts_with(string $haystack, string $needle): bool
    {
        return substr($haystack, 0, strlen($needle)) === $needle;
    }
    private static function is_empty(?string $param)
    {
        return !isset($param) || $param == ' ';
    }
    private static function validate_query_params(array $query)
    {
        $missing = [];
        $required_fields = [
          'scope',
          'client_id',
          'response_type',
          'redirect_uri',
          'code_challenge',
          'code_challenge_method'
        ];

        foreach ($required_fields as $f) {
            if (self::is_empty($query[$f])) {
                array_push($missing, $f);
            }
        }
        if (count($missing) > 0) {
            $missing_str = implode(', ', $missing);
            $s = count($missing) > 1 ? 's' : '';
            throw new InvalidInputException("missing required parameter$s ($missing_str)");
        }

        if ($query['response_type'] !== 'code') {
            throw new InvalidInputException('unsupported flow');
        }

        if (!in_array('openid', explode(' ', $query['scope']))) {
            throw new InvalidInputException('invalid scope');
        }
    }
}
