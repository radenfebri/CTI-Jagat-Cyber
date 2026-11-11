<?php

namespace App\Domain\Assets;

final class PassiveDnsDiscovery
{
    public const SOURCE = 'dns';

    public function __construct(private DnsResolver $dns) {}

    /** @return list<array{record_type: string, value: string, source: string}> */
    public function observe(string $hostname): array
    {
        $assets = [];

        foreach ($this->dns->records($hostname, DNS_A | DNS_AAAA | DNS_CNAME) as $record) {
            if (strcasecmp(rtrim($record['host'] ?? '', '.'), $hostname) !== 0) {
                continue;
            }

            $type = $record['type'] ?? null;
            $value = match ($type) {
                'A' => $this->normalizeIp($record['ip'] ?? '', FILTER_FLAG_IPV4),
                'AAAA' => $this->normalizeIp($record['ipv6'] ?? '', FILTER_FLAG_IPV6),
                'CNAME' => DomainName::normalize($record['target'] ?? ''),
                default => null,
            };

            if ($value !== null) {
                $assets[$type.':'.$value] = ['record_type' => $type, 'value' => $value, 'source' => self::SOURCE];
            }
        }

        return array_values($assets);
    }

    private function normalizeIp(string $value, int $family): ?string
    {
        if (! filter_var($value, FILTER_VALIDATE_IP, $family)) {
            return null;
        }

        return inet_ntop(inet_pton($value));
    }
}
