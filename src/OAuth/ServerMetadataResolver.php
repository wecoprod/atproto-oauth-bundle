<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Wecoprod\AtprotoOAuthBundle\Exception\AtprotoOAuthException;

/**
 * PDS → authorization server (oauth-protected-resource) → authorization server metadata.
 */
final class ServerMetadataResolver
{
    /** @var array<string, AuthorizationServerMetadata> */
    private array $metadataCache = [];

    public function __construct(private readonly HttpClientInterface $httpClient)
    {
    }

    /** Issuer of the authorization server that protects a PDS. */
    public function issuerForPds(string $pdsUrl): string
    {
        $origin = self::origin($pdsUrl);

        try {
            $metadata = $this->httpClient->request('GET', $origin.'/.well-known/oauth-protected-resource', ['timeout' => 10, 'max_redirects' => 0])->toArray();
        } catch (HttpExceptionInterface $e) {
            throw new AtprotoOAuthException(\sprintf('Unable to read the OAuth metadata of the PDS %s.', $origin), 0, $e);
        }

        $servers = $metadata['authorization_servers'] ?? null;
        if (($metadata['resource'] ?? null) !== $origin || !\is_array($servers) || \count($servers) !== 1 || !\is_string($servers[0] ?? null)) {
            throw new AtprotoOAuthException(\sprintf('The PDS %s returned invalid OAuth protected resource metadata.', $origin));
        }

        return self::origin($servers[0]);
    }

    public function authorizationServer(string $issuer): AuthorizationServerMetadata
    {
        $issuer = self::origin($issuer);
        if (isset($this->metadataCache[$issuer])) {
            return $this->metadataCache[$issuer];
        }

        try {
            $metadata = $this->httpClient->request('GET', $issuer.'/.well-known/oauth-authorization-server', ['timeout' => 10, 'max_redirects' => 0])->toArray();

            return $this->metadataCache[$issuer] = AuthorizationServerMetadata::fromArray($issuer, $metadata);
        } catch (HttpExceptionInterface|\InvalidArgumentException $e) {
            throw new AtprotoOAuthException(\sprintf('Unable to use the authorization server %s: %s', $issuer, $e->getMessage()), 0, $e);
        }
    }

    /**
     * A URL typed by the user can be a PDS or an authorization server (e.g. https://bsky.social, which is both an entryway and an AS).
     */
    public function authorizationServerForUrl(string $url): AuthorizationServerMetadata
    {
        try {
            return $this->authorizationServer($this->issuerForPds($url));
        } catch (AtprotoOAuthException) {
            return $this->authorizationServer($url);
        }
    }

    public static function origin(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? null) !== 'https' || !isset($parts['host'])) {
            throw new AtprotoOAuthException(\sprintf('"%s" is not an https URL.', $url));
        }

        return 'https://'.strtolower($parts['host']).(isset($parts['port']) ? ':'.$parts['port'] : '');
    }
}
