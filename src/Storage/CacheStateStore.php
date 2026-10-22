<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Storage;

use Psr\Cache\CacheItemPoolInterface;
use Wecoprod\AtprotoOAuthBundle\OAuth\AuthorizationState;

/**
 * Default state store. The state holds a DPoP private key and the PKCE verifier for a few minutes:
 * use a pool that is not shared with untrusted parties.
 */
final class CacheStateStore implements StateStoreInterface
{
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly int $ttl = 600,
    ) {
    }

    public function save(AuthorizationState $state): void
    {
        $item = $this->cache->getItem(self::key($state->state));
        $item->set($state->toArray());
        $item->expiresAfter($this->ttl);
        $this->cache->save($item);
    }

    public function consume(string $state): ?AuthorizationState
    {
        if ($state === '' || \strlen($state) > 256) {
            return null;
        }

        $item = $this->cache->getItem(self::key($state));
        if (!$item->isHit()) {
            return null;
        }
        $this->cache->deleteItem(self::key($state));

        $data = $item->get();

        return \is_array($data) ? AuthorizationState::fromArray($data) : null;
    }

    private static function key(string $state): string
    {
        return 'atproto_oauth_state_'.hash('sha256', $state);
    }
}
