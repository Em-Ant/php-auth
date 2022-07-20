<?php

namespace AuthServer\Models;

use DateTime;

class User implements \JsonSerializable
{
  private string $id;
  private string $realm_id;
  private string $name;
  private string $email;
  private string $password;
  private array $scopes;
  private DateTime $created_at;
  private bool $valid;

  public function __construct(
    string $id,
    string $realm_id,
    string $name,
    string $email,
    string $password,
    string $scopes,
    string $created_at,
    ?bool $valid = true
  ) {
    $this->id = $id;
    $this->realm_id = $realm_id;
    $this->name = $name;
    $this->email = $email;
    $this->password = $password;
    $this->scopes = explode(' ', $scopes);
    $this->created_at =
      \DateTime::createFromFormat('Y-m-d H:i:s', $created_at);
    $this->valid = $valid;
  }

  public function get_id(): string
  {
    return $this->id;
  }
  public function get_realm_id(): string
  {
    return $this->realm_id;
  }
  public function get_name(): string
  {
    return $this->name;
  }
  public function get_email(): string
  {
    return $this->email;
  }
  public function get_password(): string
  {
    return $this->password;
  }
  public function get_scopes(): array
  {
    return $this->scopes;
  }
  public function get_created_at(): \DateTime
  {
    return $this->created_at;
  }
  public function get_valid(): bool
  {
    return $this->valid;
  }

  public function jsonSerialize()
  {
    $data = get_object_vars($this);
    $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');

    return $data;
  }
}
