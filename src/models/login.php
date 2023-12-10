<?php

namespace AuthServer\Models;

use DateTime;
use DateTimeZone;

class Login implements \JsonSerializable
{
  private string $id;
  private ?string $session_id;
  private string $client_id;
  private string $state;
  private string $nonce;
  private string $scope;
  private string $redirect_uri;
  private string $response_mode;
  private DateTime $created_at;
  private ?string $code;
  private ?string $code_challenge;
  private ?DateTime $authenticated_at;
  private ?string $refresh_token;
  private ?DateTime $updated_at;
  private string $status;

  public function __construct(
    string $id,
    string $client_id,
    string $state,
    string $nonce,
    string $scope,
    string $redirect_uri,
    string $response_mode,
    ?string $created_at,
    ?string $session_id,
    ?string $authenticated_at,
    ?string $code,
    ?string $code_challenge,
    ?string $updated_at,
    ?string $refresh_token,
    ?string $status = 'PENDING'
  ) {
    $this->id = $id;
    $this->session_id = $session_id;
    $this->client_id = $client_id;
    $this->state = $state;
    $this->nonce = $nonce;
    $this->scope = $scope;
    $this->redirect_uri = $redirect_uri;
    $this->response_mode = $response_mode;
    $this->code = $code;
    $this->code_challenge = $code_challenge;
    $this->refresh_token = $refresh_token;
    $utc = new DateTimeZone('UTC');
    $this->created_at = is_null($created_at) ?
      date_create() :
      \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
    $this->updated_at =
      \DateTime::createFromFormat('Y-m-d H:i:s', $updated_at, $utc) ?: null;
    $this->authenticated_at =
      \DateTime::createFromFormat('Y-m-d H:i:s', $authenticated_at, $utc) ?: null;
    $this->status = is_null($status) ? '' : $status;
  }

  public function get_id(): string
  {
    return $this->id;
  }
  public function get_session_id(): string
  {
    return $this->session_id;
  }
  public function get_client_id(): string
  {
    return $this->client_id;
  }
  public function get_state(): string
  {
    return $this->state;
  }
  public function get_nonce(): string
  {
    return $this->nonce;
  }
  public function get_scope(): string
  {
    return $this->scope;
  }
  public function get_redirect_uri(): string
  {
    return $this->redirect_uri;
  }
  public function get_response_mode(): string
  {
    return $this->response_mode;
  }
  public function get_code(): ?string
  {
    return $this->code;
  }
  public function get_code_challenge(): ?string
  {
    return $this->code_challenge;
  }
  public function get_refresh_token(): ?string
  {
    return $this->refresh_token;
  }
  public function get_created_at(): \DateTime
  {
    return $this->created_at;
  }
  public function get_authenticated_at(): ?\DateTime
  {
    return $this->authenticated_at;
  }
  public function get_updated_at(): ?\DateTime
  {
    return $this->updated_at;
  }
  public function get_status(): string
  {
    return $this->status;
  }

  public function jsonSerialize()
  {
    $data = get_object_vars($this);
    $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
    $data['authenticated_at'] = isset($data['authenticated_at']) ?
      $data['authenticated_at']->format('Y-m-d H:i:s') :
      null;
    $data['updated_at'] = isset($data['updated_at']) ?
      $data['updated_at']->format('Y-m-d H:i:s') :
      null;

    return $data;
  }
}
