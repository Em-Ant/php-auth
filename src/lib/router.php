<?php

declare(strict_types=1);

namespace AuthServer\Lib;

use AuthServer\Lib\Utils;

class Router
{
  private $_routes = array();
  private $_path = '';

  public function __construct(?string $path = null)
  {
    if (!isset($path)) {
      $path = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : "";
    }
    $this->_path = '/' . trim($path, '/') . "/";
  }

  public function get(string $route, callable $handler)
  {
    $this->route('GET', $route, $handler);
  }
  public function post(string $route, callable $handler)
  {
    $this->route('POST', $route, $handler);
  }
  public function patch(string $route, callable $handler)
  {
    $this->route('PATCH', $route, $handler);
  }
  public function put(string $route, callable $handler)
  {
    $this->route('PUT', $route, $handler);
  }
  public function delete(string $route, callable $handler)
  {
    $this->route('DELETE', $route, $handler);
  }
  public function use(callable $handler)
  {
    $this->route('ALL', null, $handler);
  }
  public function all(string $route, callable $handler)
  {
    $this->route('ALL', $route, $handler);
  }

  public function run()
  {
    try {
      $params = array();
      foreach ($this->_routes as $r) {
        extract($r);
        if ($method == $_SERVER['REQUEST_METHOD'] || $method == "ALL") {
          if (is_null($route)) {
            $handler();
            continue;
          }
          $m = $this->matchHelper($route, $params);
          if ($m) {
            return $handler($params);
          }
        }
      }
    } catch (\Exception $e) {
      Utils::unknown_error();
    }
  }

  private function route(string $method, ?string $route, callable $handler)
  {
    array_push(
      $this->_routes,
      array(
        'method' => $method,
        'route' => $route,
        'handler' => $handler
      )
    );
  }
  private function matchHelper(string $route, array &$params)
  {
    preg_match_all("/\{(.+)\}/U", $route, $params_keys);
    $params_keys = $params_keys[1];
    $r = "#" . $route . "\/$#";
    $route_regex = preg_replace("/\{.+\}/U", "(.+)", $r);
    $m = preg_match($route_regex, $this->_path, $params_values);
    if ($m) {
      // extract and remove the matching string
      $match = array_splice($params_values, 0, 1)[0];
      $params = array_combine($params_keys, $params_values);
    }
    return $m;
  }
}
