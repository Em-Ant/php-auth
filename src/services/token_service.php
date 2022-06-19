<?php

declare(strict_types=1);

namespace AuthServer\Services;

class TokenService
{
  private string $public_key;
  private string $private_key;


  function __construct(string $pub, string $pri)
  {
    $this->public_key = $pub;
    $this->private_key = $pri;
  }

  function validateToken(string $token): int
  {
    $t = explode('.', $token);
    $header = json_decode(self::b64UrlDecode($t[0]), true);

    if ($header['alg'] != 'RS256') return 0;

    $data = "$t[0].$t[1]";
    $signature = self::b64UrlDecode($t[2]);

    return openssl_verify(
      $data,
      $signature,
      $this->public_key,
      "sha256WithRSAEncryption"
    );
  }

  function createToken(array $payload): string
  {

    $header = json_encode(['typ' => 'JWT', 'alg' => 'RS256']);

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
    return json_decode(self::b64UrlDecode($t[1]));
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

    while ($b64 % 4 != 0) {
      $b64 = $b64 . '=';
    }

    return base64_decode($b64);
  }

  function createKeyPair(): array
  {

    $new_key_pair = openssl_pkey_new(array(
      "private_key_bits" => 2048,
      "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ));
    openssl_pkey_export($new_key_pair, $private_key_pem);

    $details = openssl_pkey_get_details($new_key_pair);
    $public_key_pem = $details['key'];

    return [
      "public" => $public_key_pem,
      "private" => $private_key_pem
    ];
  }
}
