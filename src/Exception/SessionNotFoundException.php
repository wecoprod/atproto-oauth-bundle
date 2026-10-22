<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Exception;

final class SessionNotFoundException extends AtprotoOAuthException
{
    public function __construct(public readonly string $did)
    {
        parent::__construct(\sprintf('No OAuth session for %s.', $did));
    }
}
