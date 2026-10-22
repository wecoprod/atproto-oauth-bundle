<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\OAuth;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Lock\LockFactory;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionNotFoundException;
use Wecoprod\AtprotoOAuthBundle\Exception\SessionRevokedException;
use Wecoprod\AtprotoOAuthBundle\Storage\SessionStoreInterface;

/**
 * Returns sessions with a valid access token, refreshing them when needed.
 *
 * Refresh tokens are single use: two workers refreshing the same session at once would leave one of them with a dead
 * token. With symfony/lock installed, refreshes of a session are serialized and the second worker reuses the first one's result.
 */
final class SessionManager
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly OAuthClient $client,
        private readonly SessionStoreInterface $store,
        private readonly ?LockFactory $lockFactory = null,
        ?LoggerInterface $logger = null,
        private readonly int $refreshLeewaySeconds = 60,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @param string|null $staleAccessToken pass the token the PDS just rejected to force a refresh
     *
     * @throws SessionNotFoundException
     * @throws SessionRevokedException the user must sign in again (the session is removed from the store)
     */
    public function getSession(string $did, ?string $staleAccessToken = null): Session
    {
        $session = $this->load($did);
        if (!$this->needsRefresh($session, $staleAccessToken)) {
            return $session;
        }

        $lock = $this->lockFactory?->createLock('atproto_oauth_refresh_'.hash('sha256', $did), 30);
        $lock?->acquire(true);

        try {
            // Another process may have refreshed while we waited for the lock
            $session = $this->load($did);
            if (!$this->needsRefresh($session, $staleAccessToken)) {
                return $session;
            }

            try {
                $session = $this->client->refresh($session);
            } catch (SessionRevokedException $e) {
                $this->store->delete($did);
                $this->logger->notice('atproto OAuth session revoked for {did}', ['did' => $did]);

                throw $e;
            }

            $this->store->save($session);

            return $session;
        } finally {
            $lock?->release();
        }
    }

    /** Revokes the tokens at the authorization server (best effort) and removes the session. */
    public function revoke(string $did): void
    {
        $session = $this->store->get($did);
        if ($session === null) {
            return;
        }

        try {
            $this->client->revoke($session);
        } catch (\Throwable $e) {
            $this->logger->warning('atproto OAuth revocation failed for {did}: {error}', ['did' => $did, 'error' => $e->getMessage()]);
        }

        $this->store->delete($did);
    }

    private function load(string $did): Session
    {
        return $this->store->get($did) ?? throw new SessionNotFoundException($did);
    }

    private function needsRefresh(Session $session, ?string $staleAccessToken): bool
    {
        if ($staleAccessToken !== null && hash_equals($session->accessToken, $staleAccessToken)) {
            return true;
        }

        return $session->isExpired($this->refreshLeewaySeconds);
    }
}
