<?php

declare(strict_types=1);

namespace AuthServer\Lib;

class Utils
{
    public static function send_json($data)
    {
        header('Content-Type: text/javascript; charset=utf8');
        if (isset($_GET['callback'])) {
            echo $_GET['callback'].'('.json_encode($data).');';
        } else {
            header('Content-type: application/json');
            echo json_encode($data, JSON_UNESCAPED_SLASHES);
        }
    }

    public static function server_error(
        string $error_type,
        string $description,
        int $status_code
    ) {
        $data = array('error' => $error_type, 'error_description' => $description);
        http_response_code($status_code);
        self::send_json($data);
        die();
    }

    public static function unknown_error()
    {
        self::server_error('internal server error', 'unknown error', 500);
    }

    public static function enable_cors()
    {
        header('Access-Control-Allow-Origin:*');
        header('Access-Control-Allow-Headers:content-type,accept,origin');
        header('Access-Control-Allow-Methods:GET,POST,OPTIONS');
    }

    public static function parse_json_body()
    {
        if ($_SERVER['REQUEST_METHOD'] == 'POST' &&
            isset($_SERVER['HTTP_CONTENT_TYPE']) &&
            $_SERVER['HTTP_CONTENT_TYPE'] == 'application/json'
        ) {
            $raw_body = file_get_contents('php://input');
            $_POST = json_decode($raw_body, true);
        }
    }

    public static function not_found($params)
    {
        self::server_error('not found', 'resource not found', 404);
    }

    public static function read_env($file='.env')
    {
        $handle = fopen($file, 'r');
        $vars = array();
        if ($handle) {
            while (!feof($handle)) {
                $line = stream_get_line($handle, 10000, "\n");
                if (!$line || $line[0] == "#") {
                    continue;
                }
                list($key, $val) = explode("=", $line);
                if (isset($key)) {
                    $val = trim($val, "\"'");
                    $vars["ENV_$key"] = $val;
                }
            }
            fclose($handle);
        }
        return $vars;
    }
}
