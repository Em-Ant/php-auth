<?php

namespace AuthServer\Models;

class Client implements \JsonSerializable
{
  private string $id;
  private string $client_id;
  private string $client_secret;
  private array $scopes;
  private string $uri;
  private \DateTime $created_at;


  public function __construct(
    string $id,
    string $client_id,
    ?string $client_secret,
    string $scopes,
    string $uri,
    string $created_at
  ) {
    $this->id = $id;
    $this->client_id = $client_id;
    $this->uri = $uri;
    $this->scopes = explode(' ', $scopes);
    $this->client_secret = $client_secret;
    $this->created_at =
      \DateTime::createFromFormat('Y-m-d H:i:s', $created_at);
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
  public function get_scopes()
  {
    return $this->scopes;
  }
  public function get_created_at(): \DateTime
  {
    return $this->created_at;
  }

  public function jsonSerialize()
  {
    return get_object_vars($this);
  }
}
