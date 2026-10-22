<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

final class NativeDnsResolver implements DnsResolverInterface
{
    public function txt(string $host): array
    {
        $records = @dns_get_record($host, DNS_TXT);
        if (!\is_array($records)) {
            return [];
        }

        $values = [];
        foreach ($records as $record) {
            if (isset($record['txt']) && \is_string($record['txt'])) {
                $values[] = $record['txt'];
            }
        }

        return $values;
    }
}
