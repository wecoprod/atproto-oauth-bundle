<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Exception;

/**
 * The authorization server refused the refresh token (revoked, expired or already used): the user has to reconnect.
 * The session has already been removed from the store.
 */
final class SessionRevokedException extends AtprotoOAuthException
{
    public function __construct(public readonly string $did, ?\Throwable $previous = null)
    {
        parent::__construct(\sprintf('The OAuth session for %s is no longer valid, the user must sign in again.', $did), 0, $previous);
    }
}
