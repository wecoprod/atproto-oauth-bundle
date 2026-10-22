<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Wecoprod\AtprotoOAuthBundle\Exception\IdentityResolutionException;

/**
 * Handle → DID (DNS TXT, then HTTPS well-known) and DID → DID document (did:plc, did:web).
 */
final class IdentityResolver
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly DnsResolverInterface $dnsResolver = new NativeDnsResolver(),
        private readonly string $plcDirectoryUrl = 'https://plc.directory',
    ) {
    }

    /**
     * Resolves a handle or a DID to its DID, verified handle and PDS.
     */
    public function resolve(string $handleOrDid): ResolvedIdentity
    {
        $input = trim($handleOrDid);
        if (Syntax::isDid($input)) {
            $document = $this->resolveDid($input);
            $handle = $document->handle !== null && $this->handleResolvesTo($document->handle, $input) ? $document->handle : null;
        } else {
            $handle = Syntax::normalizeHandle($input);
            if (!Syntax::isHandle($handle)) {
                throw new IdentityResolutionException(\sprintf('"%s" is neither a valid handle nor a DID.', $handleOrDid));
            }
            $did = $this->resolveHandle($handle);
            $document = $this->resolveDid($did);
            // The DID document must claim the handle back, otherwise anyone could point a domain at someone else's DID
            if ($document->handle !== $handle) {
                throw new IdentityResolutionException(\sprintf('The DID document of %s does not confirm the handle %s.', $did, $handle));
            }
        }

        if ($document->pdsUrl === null) {
            throw new IdentityResolutionException(\sprintf('The DID document of %s declares no PDS.', $document->did));
        }

        return new ResolvedIdentity($document->did, $handle, $document->pdsUrl);
    }

    public function resolveHandle(string $handle): string
    {
        $handle = Syntax::normalizeHandle($handle);
        if (!Syntax::isHandle($handle)) {
            throw new IdentityResolutionException(\sprintf('Invalid handle "%s".', $handle));
        }

        $dnsDids = [];
        foreach ($this->dnsResolver->txt('_atproto.'.$handle) as $txt) {
            if (str_starts_with($txt, 'did=') && Syntax::isDid(substr($txt, 4))) {
                $dnsDids[] = substr($txt, 4);
            }
        }
        $dnsDids = array_values(array_unique($dnsDids));
        if (\count($dnsDids) === 1) {
            return $dnsDids[0];
        }
        if (\count($dnsDids) > 1) {
            throw new IdentityResolutionException(\sprintf('The handle %s has several DIDs in DNS.', $handle));
        }

        try {
            $response = $this->httpClient->request('GET', 'https://'.$handle.'/.well-known/atproto-did', [
                'max_redirects' => 0,
                'timeout' => 10,
            ]);
            $did = $response->getStatusCode() === 200 ? trim($response->getContent()) : '';
        } catch (HttpExceptionInterface $e) {
            throw new IdentityResolutionException(\sprintf('Unable to resolve the handle %s.', $handle), 0, $e);
        }

        if (!Syntax::isDid($did)) {
            throw new IdentityResolutionException(\sprintf('Unable to resolve the handle %s.', $handle));
        }

        return $did;
    }

    public function resolveDid(string $did): DidDocument
    {
        if (str_starts_with($did, 'did:plc:')) {
            $url = rtrim($this->plcDirectoryUrl, '/').'/'.$did;
        } elseif (str_starts_with($did, 'did:web:')) {
            $host = substr($did, 8);
            // Only bare hostnames: did:web with a path or a port is not supported by atproto
            if (!Syntax::isHandle($host)) {
                throw new IdentityResolutionException(\sprintf('Unsupported did:web "%s".', $did));
            }
            $url = 'https://'.$host.'/.well-known/did.json';
        } else {
            throw new IdentityResolutionException(\sprintf('Unsupported DID method in "%s".', $did));
        }

        try {
            $document = $this->httpClient->request('GET', $url, ['timeout' => 10])->toArray();

            return DidDocument::fromArray($did, $document);
        } catch (HttpExceptionInterface|\InvalidArgumentException $e) {
            throw new IdentityResolutionException(\sprintf('Unable to resolve %s.', $did), 0, $e);
        }
    }

    private function handleResolvesTo(string $handle, string $did): bool
    {
        try {
            return $this->resolveHandle($handle) === $did;
        } catch (IdentityResolutionException) {
            return false;
        }
    }
}
