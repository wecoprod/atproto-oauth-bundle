<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

/**
 * What the client remembers between the redirect to the authorization server and the callback.
 */
final class AuthorizationState
{
    /**
     * @param array<string, scalar|null> $appState data of the application, given back by callback() (e.g. the local user id)
     */
    public function __construct(
        public readonly string $state,
        public readonly string $issuer,
        public readonly string $pkceVerifier,
        public readonly string $dpopKeyPem,
        public readonly string $redirectUri,
        public readonly ?string $expectedDid,
        public readonly array $appState = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['state'],
            (string) $data['issuer'],
            (string) $data['pkceVerifier'],
            (string) $data['dpopKeyPem'],
            (string) $data['redirectUri'],
            isset($data['expectedDid']) ? (string) $data['expectedDid'] : null,
            (array) ($data['appState'] ?? []),
        );
    }
}
