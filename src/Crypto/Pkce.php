<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Crypto;

final class Pkce
{
    public static function verifier(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    public static function challenge(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }
}
