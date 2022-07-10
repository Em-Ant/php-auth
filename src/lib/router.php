<?php

declare(strict_types=1);

namespace AuthServer\Lib;


class Router
{
  private $_routes = array();

  public function get(string $path, ...$args)
  {
    $this->_route('GET', $path, ...$args);
  }
  public function post(string $path, ...$args)
  {
    $this->_route('POST', $path, ...$args);
  }
  public function patch(string $path, ...$args)
  {
    $this->_route('PATCH', $path, $args);
  }
  public function put(string $path, ...$args)
  {
    $this->_route('PUT', $path, ...$args);
  }
  public function delete(string $path, ...$args)
  {
    $this->_route('DELETE', $path, ...$args);
  }
  public function use(...$args)
  {
    $this->_route('USE', ...$args);
  }
  public function all(string $path, ...$args)
  {
    $this->_route('ALL', $path, ...$args);
  }

  public function run(?array $context = [])
  {
    $shared_ctx = $context;
    try {
      foreach ($this->_routes as $r) {
        extract($r);

        $mount_path = (isset($context['mount_path']) ?
          $context['mount_path'] :
          ''
        ) . $route ?: '';

        $server_path = self::get_path_info();

        $_ctx = $shared_ctx;
        $is_root_middlware = $method == 'USE' && is_null($route);
        if ($is_root_middlware) $_ctx = &$shared_ctx;

        if (!$_ctx) {
          $_ctx['method'] = $_SERVER['REQUEST_METHOD'];
          $_ctx['path'] = $server_path;
          $_ctx['query'] = $_GET;
          $_ctx['params'] = [];
          $_ctx['body'] = $_POST;

          $headers = [];
          foreach ((getallheaders() ?: []) as $key => $value) {
            $headers[strtolower($key)] = $value;
          }
          $_ctx['headers'] = $headers;
        }

        $_ctx['mount_path'] = $mount_path;

        if (
          $method == $_SERVER['REQUEST_METHOD'] ||
          $method == "ALL" || $method == 'USE'
        ) {

          $params = [];
          $match = self::match_helper(
            $mount_path,
            $server_path,
            $method != 'USE',
            $params
          );

          if ($match) {
            $_ctx['params'] = $params;
            self::call_handlers($_ctx, $handlers);
            continue;
          }
        }
      }
    } catch (\Exception $e) {
      error_log(print_r("unhandled error $e", TRUE));
      Utils::unknown_error();
    }
  }

  private function _route($method, ...$args)
  {
    $route = is_string($args[0]) ?
      array_splice($args, 0, 1)[0] :
      null;

    if (count($args) == 0) {
      throw new \BadMethodCallException(
        "at least one callable handler must be provided"
      );
    }

    array_push(
      $this->_routes,
      array(
        'method' => $method,
        'route' => $route,
        'handlers' => $args
      )
    );
  }

  private static function match_helper(
    string $path,
    string $server_path,
    bool $match_path_end,
    array &$params
  ) {

    $end_delimiter = $match_path_end ? '$' : '';
    $r = "#^" . $path . "$end_delimiter#";
    $route_regex = preg_replace("/\{.+\}/U", "(.+)", $r);

    $m = preg_match(
      $route_regex,
      $server_path,
      $params_values
    );

    if (!$m) return false;

    preg_match_all("/\{(.+)\}/U", $path, $params_keys);
    $params_keys = $params_keys[1];

    array_splice($params_values, 0, 1);
    $params = array_combine($params_keys, $params_values);

    return true;
  }

  private static function call_handlers(array &$ctx, array $handlers): void
  {
    foreach ($handlers as $h) {
      $h($ctx);
    }
  }

  private static function get_path_info()
  {
    if (!isset($_SERVER['PATH_INFO'])) return '/';
    return '/' . trim($_SERVER['PATH_INFO'], '/');
  }

  public static function parse_json_body(array &$ctx)
  {
    if (
      $_SERVER['REQUEST_METHOD'] == 'POST' &&
      isset($_SERVER['HTTP_CONTENT_TYPE']) &&
      $_SERVER['HTTP_CONTENT_TYPE'] == 'application/json'
    ) {
      $raw_body = file_get_contents('php://input');
      $ctx['body'] = json_decode($raw_body, true);
      error_log(print_r($ctx['body'], true));
    }
  }

  public static function parse_basic_auth(array &$ctx)
  {
    $headers = $ctx['headers'];
    if (!isset($headers['authorization'])) return;

    $h = explode(' ', $headers['authorization']);
    if ($h[0] != 'Basic') return;

    $cred = explode(':', base64_decode($h[1]));
    $ctx['basic_auth_user'] = $cred[0];
    $ctx['basic_auth_pwd'] = $cred[1];
  }
}
