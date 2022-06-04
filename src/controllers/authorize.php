<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Lib\Utils;

require_once 'src/lib/utils.php';

class Authorize
{
    public function auth(array $params)
    {
        self::validate_query_params();

        Utils\sendJson(array(status => 'ok'));
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
            self::is_empty($code_challenge)
        ) {
            Utils\serverError('missing required parameters', 400);
        }

        if ($response_type !== 'code') {
            Utils\serverError('unsupported flow', 400);
        }

        if (!in_array('oidc', explode(' ', $scope))) {
            Utils\serverError('invalid scope', 400);
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
}
