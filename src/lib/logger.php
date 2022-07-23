<?php

namespace AuthServer\Lib;

use AuthServer\Interfaces\Logger as ILogger;


class Logger implements ILogger
{

  private static $log_level_integers = [
    'debug' => 7,
    'info' => 6,
    'warning' => 4,
    'error' => 3
  ];

  protected $log = [];
  private string $log_dir;
  private string $log_file_name;
  private bool $log_file_append;
  private string $log_level;

  private $output_streams = [];

  public function __construct(
    ?string $level = 'info',
    ?bool $print_log = true,
    ?bool $write_log = false,
    ?string $log_file_name = 'log.log',
    ?string $log_dir = __DIR__,
    ?bool $log_file_append = true
  ) {
    $this->log_level = $level;
    $this->print_log = $print_log;
    $this->write_log = $write_log;
    $this->log_file_name = $log_file_name;
    $this->log_dir = $log_dir;
    $this->log_file_append = $log_file_append;

    if (true === $print_log) {
      $this->output_streams['stdout'] = fopen('php://stdout', 'wb');
    }

    if (
      true === $write_log &&
      (file_exists($this->log_dir) || mkdir($this->log_dir))
    ) {

      $log_file_path = implode(DIRECTORY_SEPARATOR, [$this->log_dir, $this->log_file_name]);
      $mode = $this->log_file_append ? "a" : "w";
      $this->output_streams[$log_file_path] = fopen($log_file_path, $mode);
    }
  }

  public function debug(string $message, ?string $name = ''): void
  {
    $this->add($message, $name, 'debug');
  }
  public function info(string $message, ?string $name = ''): void
  {
    $this->add($message, $name, 'info');
  }
  public function warning(string $message, ?string $name = ''): void
  {
    $this->add($message, $name, 'warning');
  }
  public function error(string $message, ?string $name = ''): void
  {
    $this->add($message, $name, 'error');
  }
  public function clear_log(): void
  {
    $this->log = [];
  }

  private function add($message, $name = '', $level = 'debug'): void
  {
    if (
      self::$log_level_integers[$level] >
      self::$log_level_integers[$this->log_level]
    ) {
      return;
    }

    /* Create the log entry */
    $log_entry = [
      'timestamp' => time(),
      'name' => $name,
      'message' => $message,
      'level' => $level,
    ];

    $this->log[] = $log_entry;

    if (count($this->output_streams) > 0) {
      $output_line = self::format_log_entry($log_entry) . PHP_EOL;
      foreach ($this->output_streams as $stream) {
        fputs($stream, $output_line);
      }
    }
  }

  private static function format_log_entry(array $log_entry): string
  {
    $log_line = "";

    if (!empty($log_entry)) {

      /* Make sure the log entry is stringified */
      $log_entry = array_map(function ($v) {
        return print_r($v, true);
      }, $log_entry);

      /* Build a line of the pretty log */
      $log_line .= date('[D M d H:i:s Y]', $log_entry['timestamp']) . " ";
      $log_line .= self::get_request_id() . ' ';
      $log_line .= "[" . strtoupper($log_entry['level']) . "] ";
      if (!empty($log_entry['name'])) {
        $log_line .= $log_entry['name'] . " => ";
      }
      $log_line .= $log_entry['message'];
    }

    return $log_line;
  }

  private static function get_request_id()
  {
    return ($_SERVER['REMOTE_ADDR'] ?: $_SERVER['HTTP_X_FORWARDED_FOR'])
      . ':' . $_SERVER['REMOTE_PORT'];
  }
}
