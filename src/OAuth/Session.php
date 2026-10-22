<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;

/**
 * An authenticated OAuth session for one account. Holds secrets (tokens, DPoP private key): store it encrypted.
 */
final class Session
{
    public function __construct(
        public readonly string $did,
        public readonly ?string $handle,
        public readonly string $pdsUrl,
        public readonly string $issuer,
        public readonly string $accessToken,
        public readonly ?string $refreshToken,
        public readonly ?\DateTimeImmutable $expiresAt,
        public readonly string $scope,
        public readonly string $dpopKeyPem,
    ) {
    }

    public function dpopKey(): EcKey
    {
        return EcKey::fromPem($this->dpopKeyPem);
    }

    public function isExpired(int $leewaySeconds = 60): bool
    {
        return $this->expiresAt !== null && $this->expiresAt->getTimestamp() - $leewaySeconds <= time();
    }

    public function withTokens(string $accessToken, ?string $refreshToken, ?\DateTimeImmutable $expiresAt, string $scope): self
    {
        return new self($this->did, $this->handle, $this->pdsUrl, $this->issuer, $accessToken, $refreshToken, $expiresAt, $scope, $this->dpopKeyPem);
    }

    /**
     * @return array{did: string, handle: ?string, pdsUrl: string, issuer: string, accessToken: string, refreshToken: ?string, expiresAt: ?int, scope: string, dpopKey: string}
     */
    public function toArray(): array
    {
        return [
            'did' => $this->did,
            'handle' => $this->handle,
            'pdsUrl' => $this->pdsUrl,
            'issuer' => $this->issuer,
            'accessToken' => $this->accessToken,
            'refreshToken' => $this->refreshToken,
            'expiresAt' => $this->expiresAt?->getTimestamp(),
            'scope' => $this->scope,
            'dpopKey' => $this->dpopKeyPem,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['did'],
            isset($data['handle']) ? (string) $data['handle'] : null,
            (string) $data['pdsUrl'],
            (string) $data['issuer'],
            (string) $data['accessToken'],
            isset($data['refreshToken']) ? (string) $data['refreshToken'] : null,
            isset($data['expiresAt']) ? (new \DateTimeImmutable())->setTimestamp((int) $data['expiresAt']) : null,
            (string) $data['scope'],
            (string) $data['dpopKey'],
        );
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public static function fromJson(string $json): self
    {
        return self::fromArray(json_decode($json, true, 512, JSON_THROW_ON_ERROR));
    }
}
