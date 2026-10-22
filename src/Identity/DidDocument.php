<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

final class DidDocument
{
    /**
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public readonly string $did,
        public readonly ?string $pdsUrl,
        public readonly ?string $handle,
        public readonly array $raw,
    ) {
    }

    /**
     * @param array<string, mixed> $document
     */
    public static function fromArray(string $did, array $document): self
    {
        if (($document['id'] ?? null) !== $did) {
            throw new \InvalidArgumentException(\sprintf('The DID document id does not match %s.', $did));
        }

        $pdsUrl = null;
        foreach ((array) ($document['service'] ?? []) as $service) {
            if (!\is_array($service)) {
                continue;
            }
            $id = (string) ($service['id'] ?? '');
            if (($id === '#atproto_pds' || $id === $did.'#atproto_pds')
                && ($service['type'] ?? null) === 'AtprotoPersonalDataServer'
                && \is_string($service['serviceEndpoint'] ?? null)
            ) {
                $pdsUrl = rtrim($service['serviceEndpoint'], '/');
                break;
            }
        }

        $handle = null;
        foreach ((array) ($document['alsoKnownAs'] ?? []) as $aka) {
            if (\is_string($aka) && str_starts_with($aka, 'at://')) {
                $candidate = Syntax::normalizeHandle($aka);
                if (Syntax::isHandle($candidate)) {
                    $handle = $candidate;
                    break;
                }
            }
        }

        return new self($did, $pdsUrl, $handle, $document);
    }
}
