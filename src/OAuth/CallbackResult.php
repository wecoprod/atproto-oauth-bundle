<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

final class CallbackResult
{
    /**
     * @param array<string, scalar|null> $appState the data given to authorize()
     */
    public function __construct(
        public readonly Session $session,
        public readonly array $appState,
    ) {
    }
}
