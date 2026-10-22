<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

final class AuthorizationServerMetadata
{
    /**
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorizationEndpoint,
        public readonly string $tokenEndpoint,
        public readonly string $pushedAuthorizationRequestEndpoint,
        public readonly ?string $revocationEndpoint,
        public readonly array $raw,
    ) {
    }

    /**
     * Checks the requirements of the atproto OAuth profile.
     *
     * @param array<string, mixed> $metadata
     */
    public static function fromArray(string $expectedIssuer, array $metadata): self
    {
        if (($metadata['issuer'] ?? null) !== $expectedIssuer) {
            throw new \InvalidArgumentException(\sprintf('The authorization server metadata issuer does not match %s.', $expectedIssuer));
        }

        foreach (['authorization_endpoint', 'token_endpoint', 'pushed_authorization_request_endpoint'] as $endpoint) {
            if (!\is_string($metadata[$endpoint] ?? null) || !str_starts_with($metadata[$endpoint], 'https://')) {
                throw new \InvalidArgumentException(\sprintf('The authorization server metadata has no valid %s.', $endpoint));
            }
        }

        $requirements = [
            'authorization_response_iss_parameter_supported' => true,
            'require_pushed_authorization_requests' => true,
            'client_id_metadata_document_supported' => true,
        ];
        foreach ($requirements as $field => $value) {
            if (($metadata[$field] ?? null) !== $value) {
                throw new \InvalidArgumentException(\sprintf('The authorization server does not support %s.', $field));
            }
        }

        $lists = [
            'scopes_supported' => 'atproto',
            'dpop_signing_alg_values_supported' => 'ES256',
            'token_endpoint_auth_methods_supported' => 'private_key_jwt',
            'code_challenge_methods_supported' => 'S256',
        ];
        foreach ($lists as $field => $value) {
            if (!\in_array($value, (array) ($metadata[$field] ?? []), true)) {
                throw new \InvalidArgumentException(\sprintf('The authorization server does not list %s in %s.', $value, $field));
            }
        }

        $revocation = $metadata['revocation_endpoint'] ?? null;

        return new self(
            $expectedIssuer,
            $metadata['authorization_endpoint'],
            $metadata['token_endpoint'],
            $metadata['pushed_authorization_request_endpoint'],
            \is_string($revocation) && str_starts_with($revocation, 'https://') ? $revocation : null,
            $metadata,
        );
    }
}
