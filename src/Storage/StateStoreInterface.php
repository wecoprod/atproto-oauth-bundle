<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Storage;

use Wecoprod\AtprotoOAuthBundle\OAuth\AuthorizationState;

interface StateStoreInterface
{
    public function save(AuthorizationState $state): void;

    /** Returns the state and deletes it: a state is single use. */
    public function consume(string $state): ?AuthorizationState;
}
