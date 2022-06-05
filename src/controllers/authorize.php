<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Lib\Utils;
use AuthServer\Exceptions\BadRequestException;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/bad_request_exception.php';


class Authorize
{
    public function auth(array $params)
    {
        try {
            self::validate_query_params();

            Utils::send_json(array('status' => 'ok'));
        } catch (BadRequestException $e) {
            Utils::server_error('invalid request', $e->getMessage(), 400);
        }
    }

    private static function is_empty(?string $param)
    {
        return !isset($param) || $param == ' ';
    }

    private static function validate_query_params()
    {
        extract($_GET);

        if (self::is_empty($scope) ||
            self::is_empty($response_type) ||
            self::is_empty($redirect_uri) ||
            self::is_empty($client_id) ||
            self::is_empty($code_challenge) ||
            self::is_empty($code_challenge_method)
        ) {
            throw new BadRequestException('missing required parameters');
        }

        if ($response_type !== 'code') {
            throw new BadRequestException('unsupported flow');
        }

        if (!in_array('openid', explode(' ', $scope))) {
            throw new BadRequestException('invalid scope');
        }
    }
}


    /*

        if(isset($_GET['scope']) ) {
          $cat = ucfirst(strtolower($_GET['cat']));
          $query = $db->prepare(
            "SELECT COUNT(Quote_ID)
            FROM quotes1
            WHERE Quote_Category = :cat;"
          );
          $query->bindValue(':cat', $cat, SQLITE3_TEXT);
          $count = $query->execute()->fetchArray();
          $count = $count[0];
          $val = rand(0, $count-1);
          $query = $db->prepare(
            "SELECT Name, Quote_Category, Quote
            FROM quotes1
            WHERE Quote_Category = :cat
            LIMIT 1 OFFSET $val;"
          );
          $query->bindValue(':cat', $cat, SQLITE3_TEXT);
          $results = $query->execute();
        } else {
          $count = $db->query('SELECT COUNT(*) FROM quotes1;');
          $count = $count->fetchArray();
          $count = $count[0];
          $val = rand(1, $count);
          $results = $db->query(
            "SELECT Name, Quote_Category, Quote FROM quotes1 WHERE Quote_ID = $val;"
          );
        }

        $r = $results->fetchArray(SQLITE3_NUM);
        if(!$r) {
          $data = array('text' => null, 'author' => null, 'category' => null);
        } else {
          $author = explode(',', $r[0]);
          $data = array (
            'author' => trim("$author[1] $author[0]"),
            'category' => $r[1],
            'text' => $r[2]
          );
        }
        sendJson($data);

        $db->close();
        */
