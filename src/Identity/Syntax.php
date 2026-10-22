<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

/** Syntax checks from the AT Protocol specs (handle and DID). */
final class Syntax
{
    private const HANDLE = '/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/';
    private const DID = '/^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/';

    public static function isHandle(string $value): bool
    {
        return \strlen($value) <= 253 && preg_match(self::HANDLE, $value) === 1;
    }

    public static function isDid(string $value): bool
    {
        return \strlen($value) <= 2048 && preg_match(self::DID, $value) === 1;
    }

    /** Accepts "alice.bsky.social", "@alice.bsky.social" or "at://alice.bsky.social" and returns the lowercase handle. */
    public static function normalizeHandle(string $value): string
    {
        $value = trim($value);
        if (str_starts_with($value, 'at://')) {
            $value = substr($value, 5);
        }

        return strtolower(ltrim($value, '@'));
    }
}
