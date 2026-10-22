<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Exception;

/** XRPC error returned by the PDS, e.g. {"error":"InvalidRequest","message":"..."}. */
final class XrpcException extends AtprotoOAuthException
{
    public function __construct(
        public readonly string $nsid,
        public readonly int $statusCode,
        public readonly ?string $error = null,
        ?string $message = null,
    ) {
        parent::__construct(\sprintf('%s failed (HTTP %d)%s', $nsid, $statusCode, $error !== null ? ': '.$error.($message !== null && $message !== '' ? ' - '.$message : '') : ''));
    }
}
