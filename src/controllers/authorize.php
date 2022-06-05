<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Validators\ValidateAuthorize;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/invalid_input_exception.php';

class Authorize
{
    private ValidateAuthorize $validator;

    public function __construct(ValidateAuthorize $validator)
    {
        $this->validator = $validator;
    }
    public function auth(array $params)
    {
        try {
            $this->validator->execute($_GET);

            Utils::send_json(array("status" => "ok"));
        } catch (InvalidInputException $e) {
            Utils::server_error('invalid request', $e->getMessage(), 400);
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
