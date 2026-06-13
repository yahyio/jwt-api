<?php

function b64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64url_decode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/'));
}

function jwt_sign(array $claims, string $secret, int $ttl = 3600): string
{
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $claims['iat'] = time();
    $claims['exp'] = time() + $ttl;

    $segments = [
        b64url_encode(json_encode($header)),
        b64url_encode(json_encode($claims)),
    ];
    $signature = hash_hmac('sha256', implode('.', $segments), $secret, true);
    $segments[] = b64url_encode($signature);

    return implode('.', $segments);
}

function jwt_verify(string $token, string $secret): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }

    [$head64, $body64, $sig64] = $parts;

    $header = json_decode(b64url_decode($head64), true);
    if (($header['alg'] ?? '') !== 'HS256') {
        return null;
    }

    $expected = hash_hmac('sha256', "$head64.$body64", $secret, true);
    if (!hash_equals($expected, b64url_decode($sig64))) {
        return null;
    }

    $claims = json_decode(b64url_decode($body64), true);
    if (!is_array($claims) || ($claims['exp'] ?? 0) < time()) {
        return null;
    }

    return $claims;
}
