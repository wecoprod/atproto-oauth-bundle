<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Wecoprod\AtprotoOAuthBundle\Crypto\EcKey;

final class ClientConfiguration
{
    public readonly string $keyId;
    public readonly string $jwksUri;

    /**
     * @param list<string> $redirectUris the first one is used when authorize() gets none
     */
    public function __construct(
        public readonly string $clientId,
        public readonly array $redirectUris,
        public readonly EcKey $clientKey,
        public readonly string $scope = 'atproto transition:generic',
        ?string $jwksUri = null,
        ?string $keyId = null,
        public readonly string $defaultAuthorizationServer = 'https://bsky.social',
        public readonly ?string $clientName = null,
        public readonly ?string $clientUri = null,
        public readonly ?string $logoUri = null,
        public readonly ?string $tosUri = null,
        public readonly ?string $policyUri = null,
    ) {
        if (!str_starts_with($clientId, 'https://')) {
            throw new \InvalidArgumentException('The client_id must be the https URL of the client metadata document.');
        }
        if ($redirectUris === []) {
            throw new \InvalidArgumentException('At least one redirect URI is required.');
        }
        if (!\in_array('atproto', explode(' ', $scope), true)) {
            throw new \InvalidArgumentException('The scope must include "atproto".');
        }
        // Authorization servers reject the metadata otherwise (invalid_client_metadata)
        if ($clientUri !== null && self::origin($clientUri) !== self::origin($clientId)) {
            throw new \InvalidArgumentException(\sprintf('The client_uri "%s" must have the same origin as the client_id.', $clientUri));
        }

        $this->keyId = $keyId ?? $clientKey->thumbprint();
        $this->jwksUri = $jwksUri ?? self::siblingUrl($clientId, 'jwks.json');
    }

    /**
     * The client metadata document served at the client_id URL.
     *
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return array_filter([
            'client_id' => $this->clientId,
            'application_type' => 'web',
            'client_name' => $this->clientName,
            'client_uri' => $this->clientUri,
            'logo_uri' => $this->logoUri,
            'tos_uri' => $this->tosUri,
            'policy_uri' => $this->policyUri,
            'redirect_uris' => $this->redirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'scope' => $this->scope,
            'token_endpoint_auth_method' => 'private_key_jwt',
            'token_endpoint_auth_signing_alg' => 'ES256',
            'jwks_uri' => $this->jwksUri,
            'dpop_bound_access_tokens' => true,
        ], static fn ($value) => $value !== null);
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array
    {
        return ['keys' => [$this->clientKey->publicJwk() + ['kid' => $this->keyId, 'use' => 'sig', 'alg' => 'ES256']]];
    }

    private static function siblingUrl(string $url, string $file): string
    {
        $directory = str_replace('\\', '/', \dirname(parse_url($url, \PHP_URL_PATH) ?: '/x'));

        return self::origin($url).rtrim($directory, '/').'/'.$file;
    }

    private static function origin(string $url): string
    {
        $parts = parse_url($url);

        return strtolower(($parts['scheme'] ?? 'https').'://'.($parts['host'] ?? '')).(isset($parts['port']) ? ':'.$parts['port'] : '');
    }
}
