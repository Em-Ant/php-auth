<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Models\Session;
use AuthServer\Models\Client;
use AuthServer\Models\User;

use AuthServer\Lib\Utils;

require_once 'src/lib/utils.php';
require_once 'src/models/session.php';
require_once 'src/models/client.php';
require_once 'src/models/user.php';


class TokenService
{
  private string $public_key;
  private string $private_key;
  private string $keys_id;
  private string $issuer;

  function __construct(
    string $kid,
    string $issuer
  ) {
    $this->public_key = file_get_contents("keys/$kid/public_key.pem");
    $this->private_key = file_get_contents("keys/$kid/private_key.pem");
    $this->keys_id = $kid;
    $this->issuer = $issuer;
  }

  function validateToken(string $token): int
  {
    $t = explode('.', $token);
    $header = json_decode(self::b64UrlDecode($t[0]), true);

    if ($header['alg'] != 'RS256') {
      return 0;
    }

    $data = "$t[0].$t[1]";
    $signature = self::b64UrlDecode($t[2]);

    return openssl_verify(
      $data,
      $signature,
      $this->public_key,
      "sha256WithRSAEncryption"
    );
  }

  function tokenIsExpired(string $token): bool
  {
    $decoded = $this->decodeTokenPayload($token);
    return $decoded['exp'] < time();
  }

  function createToken(array $payload): string
  {

    $header = json_encode([
      'typ' => 'JWT',
      'alg' => 'RS256',
      'kid' => $this->keys_id
    ]);

    $base64UrlHeader = self::b64UrlEncode($header);
    $base64UrlPayload = self::b64UrlEncode(json_encode($payload));

    openssl_sign(
      $base64UrlHeader . "." . $base64UrlPayload,
      $signature,
      $this->private_key,
      OPENSSL_ALGO_SHA256
    );

    $base64UrlSignature = self::b64UrlEncode($signature);
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
  }

  function decodeTokenPayload(string $token): array
  {
    $t = explode('.', $token);
    return json_decode(self::b64UrlDecode($t[1]), true);
  }

  private static function b64UrlEncode($data): string
  {
    return str_replace(
      ['+', '/', '='],
      ['-', '_', ''],
      base64_encode($data)
    );
  }

  private static function b64UrlDecode(string $data)
  {
    $b64 = str_replace(['-', '_'], ['+', '/'], $data);

    while (strlen($b64) % 4 != 0) {
      $b64 = $b64 . '=';
    }

    return base64_decode($b64);
  }

  public static function createKeys(?array $dn = [], ?int $cert_duration = 365): void
  {
    $config = array(
      "private_key_bits" => 2048,
      "private_key_type" => OPENSSL_KEYTYPE_RSA,
    );

    $dn = array_merge(array(
      "countryName"               => "IT",
      "stateOrProvinceName"       => "TR",
      "localityName"              => "Terni",
      "organizationName"          => "localhost",
      "organizationalUnitName"    => "auth",
      "commonName"                => "auth_server",
      "emailAddress"              => "test@example.com"
    ), $dn);

    $new_key_pair = openssl_pkey_new($config);

    $csr = openssl_csr_new($dn, $new_key_pair, $config);
    $cert = openssl_csr_sign(
      $csr,
      null,
      $new_key_pair,
      $cert_duration,
      $config,
      0
    );

    openssl_x509_export($cert, $x509);
    openssl_pkey_export($new_key_pair, $private_key_pem);

    $details = openssl_pkey_get_details($new_key_pair);
    $public_key_pem = $details['key'];
    $kid = bin2hex(random_bytes(6));
    $keys = [
      "kid" => $kid,
      "kty" => "RSA",
      "alg" => "RS256",
      "use" => "sig",
      "n" => base64_encode($details['rsa']['n']),
      "e" => base64_encode($details['rsa']['e']),
      "x5c" => [
        str_replace([
          '-----END CERTIFICATE-----',
          '-----BEGIN CERTIFICATE-----', ' ', "\n"
        ], '', $x509)
      ],
      "x5t" => base64_encode(openssl_x509_fingerprint($x509)),
      "x5t#sha256" => base64_encode(openssl_x509_fingerprint($x509, 'sha256')),
    ];

    $dir = "keys/$kid";
    mkdir($dir);

    file_put_contents("$dir/public_key.pem", $public_key_pem);
    file_put_contents("$dir/private_key.pem", $private_key_pem);
    file_put_contents("$dir/cert.pem", $x509);
    file_put_contents("$dir/keys.json", json_encode($keys, JSON_PRETTY_PRINT));
  }

  public function createTokenBundle(
    Session $session,
    Client $client,
    User $user,
    int $access_token_validity_seconds,
    int $refresh_token_validity_seconds,
    ?string $acr = '1'
  ): array {
    $now = time();
    $access_token = $this->createAccessToken(
      $now,
      $access_token_validity_seconds,
      $session,
      $client,
      $user,
      $acr
    );
    $id_token = $this->createIdToken(
      $now,
      $access_token_validity_seconds,
      $session,
      $client,
      $user,
      $access_token,
      $acr
    );
    $refresh_token = $this->createRefreshToken(
      $now,
      $refresh_token_validity_seconds,
      $session,
      $client,
      $user
    );

    return [
      "access_token" => $access_token,
      "expires_in" => $access_token_validity_seconds,
      "refresh_expires_in" => $refresh_token_validity_seconds,
      "refresh_token" => $refresh_token,
      "token_type" => "Bearer",
      "id_token" => $id_token,
      "not-before-policy" => 0,
      "session_state" => $session->get_session_state(),
      "scope" => join(" ", $user->get_scopes()),
    ];
  }

  private function createRefreshToken(
    int $now,
    int $validity,
    Session $session,
    Client $client,
    User $user
  ): string {
    $exp = $now + $validity;
    return $this->createToken([
      "exp" => $exp,
      "iat" => $now,
      "jti" => Utils::get_guid(),
      "iss" => $this->issuer,
      "aud" => $this->issuer,
      "sub" => $session->get_user_id(),
      "typ" => "Refresh",
      "azp" => $client->get_client_id(),
      "nonce" => $session->get_nonce(),
      "session_state" => $session->get_session_state(),
      "scope" => join(" ", $user->get_scopes()),
      "sid" => $session->get_id()
    ]);
  }

  private function createAccessToken(
    int $now,
    int $validity,
    Session $session,
    Client $client,
    User $user,
    ?string $acr = '1'
  ): string {
    $exp = $now + $validity;
    return $this->createToken([
      "exp" => $exp,
      "iat" => $now,
      "auth_time" => date_timestamp_get($session->get_authenticated_at()),
      "jti" => Utils::get_guid(),
      "iss" => $this->issuer,
      "aud" => $client->get_client_id(),
      "sub" => $session->get_user_id(),
      "typ" => "Bearer",
      "azp" => $client->get_client_id(),
      "nonce" => $session->get_nonce(),
      "session_state" => $session->get_session_state(),
      "acr" => $acr,
      "allowed-origins" => [
        $client->get_uri()
      ],
      "scope" => join(" ", $user->get_scopes()),
      "sid" => $session->get_id(),
      "preferred_username" => $user->get_email()
    ]);
  }

  private function createIdToken(
    int $now,
    int $validity,
    Session $session,
    Client $client,
    User $user,
    string $access_token,
    ?string $acr = '1'
  ): string {
    $exp = $now + $validity;
    return $this->createToken([
      "exp" => $exp,
      "iat" => $now,
      "auth_time" => date_timestamp_get($session->get_authenticated_at()),
      "jti" => Utils::get_guid(),
      "iss" => $this->issuer,
      "aud" => $client->get_client_id(),
      "sub" => $session->get_user_id(),
      "typ" => "ID",
      "azp" => $client->get_client_id(),
      "nonce" => $session->get_nonce(),
      "session_state" => $session->get_session_state(),
      "at_hash" => md5($access_token),
      "acr" => $acr,
      "sid" => $session->get_id(),
      "preferred_username" => $user->get_email()
    ]);
  }
}
