<?php

namespace AuthServer\Models;

class Client implements \JsonSerializable
{
  private string $id;
  private string $client_id;
  private string $uri;
  private string $client_secret;

  public function __construct(
    string $id,
    string $client_id,
    string $uri,
    string $client_secret
  ) {
    $this->id = $id;
    $this->client_id = $client_id;
    $this->uri = $uri;
    $this->client_secret = $client_secret;
  }

  public function get_id()
  {
    return $this->id;
  }
  public function get_client_id()
  {
    return $this->client_id;
  }
  public function get_uri()
  {
    return $this->uri;
  }
  public function get_client_secret()
  {
    return $this->client_secret;
  }

  public function jsonSerialize()
  {
    return get_object_vars($this);
  }
}
