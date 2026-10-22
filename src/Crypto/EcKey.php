<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Crypto;

/**
 * P-256 private key, used both for the client assertion (private_key_jwt) and for DPoP proofs.
 */
final class EcKey
{
    private const COORDINATE_LENGTH = 32;

    private \OpenSSLAsymmetricKey $key;

    /** @var array{kty: string, crv: string, x: string, y: string} */
    private array $publicJwk;

    private function __construct(\OpenSSLAsymmetricKey $key)
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new \InvalidArgumentException('Only P-256 (prime256v1) EC private keys are supported.');
        }

        $this->key = $key;
        $this->publicJwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Base64Url::encode(str_pad($details['ec']['x'], self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT)),
            'y' => Base64Url::encode(str_pad($details['ec']['y'], self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT)),
        ];
    }

    public static function generate(): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false) {
            throw new \RuntimeException('Unable to generate a P-256 key: '.openssl_error_string());
        }

        return new self($key);
    }

    /**
     * Accepts a PEM string, or the same PEM base64-encoded on one line (handy for environment variables).
     */
    public static function fromPem(string $pem): self
    {
        $pem = trim($pem);
        if (!str_starts_with($pem, '-----BEGIN')) {
            $decoded = base64_decode($pem, true);
            if ($decoded === false) {
                throw new \InvalidArgumentException('The private key is neither a PEM string nor a base64-encoded PEM.');
            }
            $pem = $decoded;
        }

        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new \InvalidArgumentException('Unable to read the private key.');
        }

        return new self($key);
    }

    public function toPem(): string
    {
        if (!openssl_pkey_export($this->key, $pem)) {
            throw new \RuntimeException('Unable to export the private key.');
        }

        return $pem;
    }

    /**
     * @return array{kty: string, crv: string, x: string, y: string}
     */
    public function publicJwk(): array
    {
        return $this->publicJwk;
    }

    /** RFC 7638 thumbprint, used as the default key id. */
    public function thumbprint(): string
    {
        $canonical = json_encode([
            'crv' => $this->publicJwk['crv'],
            'kty' => $this->publicJwk['kty'],
            'x' => $this->publicJwk['x'],
            'y' => $this->publicJwk['y'],
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return Base64Url::encode(hash('sha256', $canonical, true));
    }

    /**
     * ES256 signature in the JOSE format (r || s, 64 bytes), not the DER format openssl returns.
     */
    public function sign(string $data): string
    {
        if (!openssl_sign($data, $der, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Unable to sign: '.openssl_error_string());
        }

        return self::derToRaw($der);
    }

    public static function derToRaw(string $der): string
    {
        $offset = 0;
        if (\ord($der[$offset++]) !== 0x30) {
            throw new \InvalidArgumentException('Invalid DER signature.');
        }
        self::readLength($der, $offset);

        $raw = '';
        for ($i = 0; $i < 2; ++$i) {
            if (\ord($der[$offset++]) !== 0x02) {
                throw new \InvalidArgumentException('Invalid DER signature.');
            }
            $length = self::readLength($der, $offset);
            $integer = ltrim(substr($der, $offset, $length), "\0");
            $offset += $length;
            if (\strlen($integer) > self::COORDINATE_LENGTH) {
                throw new \InvalidArgumentException('Invalid DER signature.');
            }
            $raw .= str_pad($integer, self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT);
        }

        return $raw;
    }

    public static function rawToDer(string $raw): string
    {
        if (\strlen($raw) !== 2 * self::COORDINATE_LENGTH) {
            throw new \InvalidArgumentException('Invalid ES256 signature length.');
        }

        $sequence = '';
        foreach (str_split($raw, self::COORDINATE_LENGTH) as $integer) {
            $integer = ltrim($integer, "\0");
            if ($integer === '' || \ord($integer[0]) > 0x7F) {
                $integer = "\0".$integer;
            }
            $sequence .= "\x02".pack('C', \strlen($integer)).$integer;
        }

        return "\x30".pack('C', \strlen($sequence)).$sequence;
    }

    private static function readLength(string $der, int &$offset): int
    {
        $length = \ord($der[$offset++]);
        if ($length & 0x80) {
            $bytes = $length & 0x7F;
            $length = 0;
            for ($i = 0; $i < $bytes; ++$i) {
                $length = ($length << 8) | \ord($der[$offset++]);
            }
        }

        return $length;
    }
}
