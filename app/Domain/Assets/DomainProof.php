<?php

namespace App\Domain\Assets;

final class DomainProof
{
    public function __construct(private DnsResolver $dns, private AuthoritativeTxt $authoritativeTxt) {}

    public function matches(MonitoredDomain $domain): bool
    {
        if (config('cti.txt_authority.zone') === $domain->hostname) {
            return $this->authoritativeTxt->matches(
                $domain->txtName(),
                $domain->txtValue(),
                (string) config('cti.txt_authority.server'),
            );
        }

        foreach ($this->dns->records($domain->txtName(), DNS_TXT) as $record) {
            if (($record['type'] ?? null) !== 'TXT'
                || strcasecmp(rtrim($record['host'] ?? '', '.'), $domain->txtName()) !== 0) {
                continue;
            }

            $value = $record['txt'] ?? implode('', $record['entries'] ?? []);

            if (is_string($value) && hash_equals($domain->txtValue(), $value)) {
                return true;
            }
        }

        return false;
    }
}
