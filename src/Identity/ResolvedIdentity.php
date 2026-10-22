<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

final class ResolvedIdentity
{
    /**
     * @param string|null $handle only set when it resolves back to the DID (bidirectional check)
     */
    public function __construct(
        public readonly string $did,
        public readonly ?string $handle,
        public readonly string $pdsUrl,
    ) {
    }
}
