<?php

declare(strict_types=1);

namespace Wecoprod\AtprotoOAuthBundle\Identity;

interface DnsResolverInterface
{
    /**
     * @return list<string> TXT record values for the host, empty when none
     */
    public function txt(string $host): array;
}
