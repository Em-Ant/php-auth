<?php

namespace AuthServer\Models;

use DateTime;

class User implements \JsonSerializable
{
  private string $id;
  private string $email;
  private string $password;
  private array $scopes;
  private DateTime $created_at;
  private bool $valid;

  public function __construct(
    string $id,
    string $email,
    string $password,
    string $scopes,
    DateTime $created_at,
    bool $valid
  ) {
    $this->id = $id;
    $this->email = $email;
    $this->password = $password;
    $this->scopes = explode(' ', $scopes);
    $this->created_at = $created_at;
    $this->valid = $valid;
  }

  public function get_id(): string
  {
    return $this->id;
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
    return get_object_vars($this);
  }
}
