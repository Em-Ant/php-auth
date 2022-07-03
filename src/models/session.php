<?php

namespace AuthServer\Models;

use DateTime;

class Session implements \JsonSerializable
{
  private string $id;
  private string $client_id;
  private string $state;
  private string $nonce;
  private string $session_state;
  private string $redirect_uri;
  private ?string $refresh_token = null;
  private ?string $user_id = null;
  private ?string $code = null;
  private DateTime $created_at;
  private ?DateTime $authenticated_at;
  private string $status;

  public function __construct(
    string $id,
    string $client_id,
    string $state,
    string $nonce,
    ?string $session_state,
    string $redirect_uri,
    ?string $refresh_token = null,
    ?string $user_id = null,
    ?string $code = null,
    ?string $created_at = null,
    ?string $authenticated_at = null,
    ?string $status = 'PENDING'
  ) {
    $this->id = $id;
    $this->client_id = $client_id;
    $this->state = $state;
    $this->nonce = $nonce;
    $this->session_state = $session_state;
    $this->redirect_uri = $redirect_uri;
    $this->refresh_token = $refresh_token;
    $this->user_id = $user_id;
    $this->code = $code;
    $this->created_at = is_null($created_at) ?
      date_create() :
      \DateTime::createFromFormat('Y-m-d H:i:s', $created_at);
    $this->authenticated_at =
      \DateTime::createFromFormat('Y-m-d H:i:s', $authenticated_at) ?: null;
    $this->status = is_null($status) ? 'PENDING' : $status;
  }

  public function get_id(): string
  {
    return $this->id;
  }
  public function get_client_id(): string
  {
    return $this->client_id;
  }
  public function get_uri(): string
  {
    return $this->uri;
  }
  public function get_state(): string
  {
    return $this->state;
  }
  public function get_nonce(): string
  {
    return $this->nonce;
  }
  public function get_session_state(): string
  {
    return $this->session_state;
  }
  public function get_refresh_token(): string
  {
    return $this->refresh_token;
  }
  public function get_user_id(): string
  {
    return $this->user_id;
  }
  public function get_created_at(): \DateTime
  {
    return $this->created_at;
  }
  public function get_authenticated_at(): ?\DateTime
  {
    return $this->authenticated_at;
  }
  public function get_status(): string
  {
    return $this->status;
  }
  public function get_code(): string
  {
    return $this->code;
  }
  public function get_redirect_uri(): string
  {
    return $this->redirect_uri;
  }

  public function jsonSerialize()
  {
    $data = get_object_vars($this);
    $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
    return $data;
  }
}
