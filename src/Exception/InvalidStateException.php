<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Exception;

/** Unknown, expired or replayed `state` in the authorization callback. */
final class InvalidStateException extends AtprotoOAuthException
{
}
