<?php

declare(strict_types=1);

namespace Emant\BrowniePhp;

class Utils
{
  public static function send_json($data)
  {
    header('Content-Type: text/javascript; charset=utf8');
    if (isset($_GET['callback'])) {
      echo $_GET['callback'] . '(' . json_encode($data) . ');';
    } else {
      header('Content-Type: application/json');
      echo json_encode($data, JSON_UNESCAPED_SLASHES);
    }
    Utils::terminate();
  }

  public static function server_error(
    string $error_type,
    string $description,
    int $status_code
  ) {
    $data = array('error' => $error_type, 'error_description' => $description);
    http_response_code($status_code);
    self::send_json($data);
  }

  public static function unknown_error()
  {
    self::server_error('internal server error', 'unknown error', 500);
  }

  public static function not_found()
  {
    self::server_error('not found', 'resource not found', 404);
  }

  public static function read_env($file = '.env')
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
          $vars["$key"] = $val;
        }
      }
      fclose($handle);
    }
    return $vars;
  }

  public static function show_view(string $view, array $params)
  {
    extract($params);
    $view = 'src/views/' . $view . '.php';
    include 'src/views/template.php';
    Utils::terminate();
  }

  public static function get_guid($data = null): string
  {
    $data = $data ?? random_bytes(16);

    assert(strlen($data) == 16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
  }

  public static function enable_cors(?string $origin = '*')
  {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Headers: content-type,accept,origin');
    header('Access-Control-Allow-Methods: GET,POST,OPTIONS');
  }

  private static function terminate()
  {
    if (!defined('UNIT_TESTING')) {
      die();
    }
  }
}
