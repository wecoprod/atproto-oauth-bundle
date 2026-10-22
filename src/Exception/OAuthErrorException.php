<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Exception;

/** Error response from the authorization server (RFC 6749 section 5.2) or from the authorization redirect. */
final class OAuthErrorException extends AtprotoOAuthException
{
    public function __construct(
        public readonly string $error,
        public readonly ?string $errorDescription = null,
        public readonly ?int $statusCode = null,
    ) {
        parent::__construct($errorDescription !== null && $errorDescription !== '' ? \sprintf('%s: %s', $error, $errorDescription) : $error);
    }
}
