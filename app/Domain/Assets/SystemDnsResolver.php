<?php

namespace App\Domain\Assets;

use RuntimeException;

final class SystemDnsResolver implements DnsResolver
{
    public function records(string $hostname, int $type): array
    {
        $records = @dns_get_record($hostname.'.', $type);

        if ($records === false) {
            throw new RuntimeException('The DNS resolver could not complete the request.');
        }

        return array_values($records);
    }
}
