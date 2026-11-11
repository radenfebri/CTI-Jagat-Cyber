<?php

namespace App\Domain\Assets;

final class PublicTlsEndpoint
{
    public function __construct(private PassiveDnsDiscovery $dns) {}

    public function resolve(string $hostname): ?string
    {
        $visited = [];

        // Resolve at most five names, keeping the original hostname for the TLS handshake.
        for ($hop = 0; $hop < 5; $hop++) {
            if (isset($visited[$hostname])) {
                return null;
            }

            $visited[$hostname] = true;
            $records = $this->dns->observe($hostname);
            $aliases = array_values(array_filter($records, fn (array $record): bool => $record['record_type'] === 'CNAME'));
            if ($aliases !== []) {
                if (count($aliases) !== 1) {
                    return null;
                }

                $hostname = $aliases[0]['value'];

                continue;
            }

            foreach ($records as $record) {
                if (in_array($record['record_type'], ['A', 'AAAA'], true) && ObservedNetwork::isPublic($record['value'])) {
                    return $record['value'];
                }
            }

            return null;
        }

        return null;
    }
}
