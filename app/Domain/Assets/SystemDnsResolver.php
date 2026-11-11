<?php

namespace App\Domain\Assets;

use RuntimeException;

final class SystemDnsResolver implements DnsResolver
{
    public function records(string $hostname, int $type): array
    {
        $records = @dns_get_record($hostname.'.', $type);

        if ($records === false) {
            throw new RuntimeException('Resolver DNS tidak dapat menyelesaikan permintaan.');
        }

        return array_values($records);
    }
}
