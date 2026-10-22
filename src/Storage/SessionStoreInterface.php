<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Storage;

use Wecoprod\AtprotoOAuthBundle\OAuth\Session;

/**
 * Implemented by the application (e.g. a Doctrine entity column, encrypted). Sessions are keyed by DID.
 */
interface SessionStoreInterface
{
    public function get(string $did): ?Session;

    public function save(Session $session): void;

    public function delete(string $did): void;
}
