<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use Wecoprod\AtprotoOAuthBundle\Crypto\Base64Url;
use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;
use Wecoprod\AtprotoOAuthBundle\Crypto\Jwt;
use Wecoprod\AtprotoOAuthBundle\Crypto\Pkce;

final class EcKeyTest extends TestCase
{
    public function testSignatureIsAValidEs256Signature(): void
    {
        $key = EcKey::generate();

        for ($i = 0; $i < 20; ++$i) {
            $data = random_bytes(40);
            $signature = $key->sign($data);

            self::assertSame(64, \strlen($signature));
            self::assertSame(1, openssl_verify($data, EcKey::rawToDer($signature), $this->publicPem($key), OPENSSL_ALGO_SHA256));
            self::assertSame($signature, EcKey::derToRaw(EcKey::rawToDer($signature)));
        }
    }

    public function testJwtCanBeVerifiedWithThePublicKey(): void
    {
        $key = EcKey::generate();
        $jwt = Jwt::sign(['typ' => 'dpop+jwt'], ['htm' => 'POST'], $key);

        [$header, $payload, $signature] = Jwt::decode($jwt);
        self::assertSame('ES256', $header['alg']);
        self::assertSame('dpop+jwt', $header['typ']);
        self::assertSame('POST', $payload['htm']);

        $signingInput = substr($jwt, 0, strrpos($jwt, '.'));
        self::assertSame(1, openssl_verify($signingInput, EcKey::rawToDer($signature), $this->publicPem($key), OPENSSL_ALGO_SHA256));
    }

    public function testPemRoundTripAndBase64Pem(): void
    {
        $key = EcKey::generate();
        $pem = $key->toPem();

        self::assertSame($key->publicJwk(), EcKey::fromPem($pem)->publicJwk());
        self::assertSame($key->thumbprint(), EcKey::fromPem(base64_encode($pem))->thumbprint());
    }

    public function testPublicJwkShape(): void
    {
        $jwk = EcKey::generate()->publicJwk();

        self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($jwk));
        self::assertSame(32, \strlen(Base64Url::decode($jwk['x'])));
        self::assertSame(32, \strlen(Base64Url::decode($jwk['y'])));
    }

    public function testRejectsOtherCurves(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);

        $this->expectException(\InvalidArgumentException::class);
        EcKey::fromPem($pem);
    }

    public function testPkceChallengeFromRfc7636(): void
    {
        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    }

    private function publicPem(EcKey $key): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private($key->toPem()));

        return $details['key'];
    }
}
