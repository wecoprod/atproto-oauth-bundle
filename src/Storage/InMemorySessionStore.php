<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Storage;

use Wecoprod\AtprotoOAuthBundle\OAuth\Session;

/** For tests and scripts: sessions are lost at the end of the process. */
final class InMemorySessionStore implements SessionStoreInterface
{
    /** @var array<string, Session> */
    private array $sessions = [];

    public function get(string $did): ?Session
    {
        return $this->sessions[$did] ?? null;
    }

    public function save(Session $session): void
    {
        $this->sessions[$session->did] = $session;
    }

    public function delete(string $did): void
    {
        unset($this->sessions[$did]);
    }
}
