<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Crypto;

final class Jwt
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public static function sign(array $header, array $payload, EcKey $key): string
    {
        $header = ['alg' => 'ES256'] + $header;
        $signingInput = Base64Url::encode(self::json($header)).'.'.Base64Url::encode(self::json($payload));

        return $signingInput.'.'.Base64Url::encode($key->sign($signingInput));
    }

    /**
     * Decodes without verifying. For tests and debugging only.
     *
     * @return array{0: array<string, mixed>, 1: array<string, mixed>, 2: string}
     */
    public static function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (\count($parts) !== 3) {
            throw new \InvalidArgumentException('A JWT has three parts.');
        }

        return [
            json_decode(Base64Url::decode($parts[0]), true, 512, JSON_THROW_ON_ERROR),
            json_decode(Base64Url::decode($parts[1]), true, 512, JSON_THROW_ON_ERROR),
            Base64Url::decode($parts[2]),
        ];
    }

    public static function randomId(): string
    {
        return Base64Url::encode(random_bytes(16));
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
