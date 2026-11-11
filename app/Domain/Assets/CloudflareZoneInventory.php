<?php

namespace App\Domain\Assets;

use Illuminate\Support\Facades\Http;
use RuntimeException;

final class CloudflareZoneInventory
{
    public const SOURCE = 'cloudflare_zone';

    public function configuredFor(MonitoredDomain $domain): bool
    {
        return preg_match('/\A[a-f0-9]{32}\z/i', (string) $domain->cloudflare_zone_id) === 1
            && filled($domain->cloudflare_api_token);
    }

    /** @return list<string> */
    public function read(MonitoredDomain $domain): array
    {
        if (! $this->configuredFor($domain)) {
            throw new RuntimeException('Zone connection is unavailable for this domain.');
        }

        $url = 'https://api.cloudflare.com/client/v4/zones/'.$domain->cloudflare_zone_id.'/dns_records';
        $client = Http::acceptJson()->withToken($domain->cloudflare_api_token)
            ->connectTimeout(2)->timeout(4)->withoutRedirecting();
        $names = [];
        $matchedZone = false;
        $pages = 1;

        for ($page = 1; $page <= $pages; $page++) {
            $response = $client->get($url, ['page' => $page, 'per_page' => 500]);
            $records = $response->json('result');
            $total = $response->json('result_info.total_pages');
            $responsePage = $response->json('result_info.page');

            if (! $response->successful() || $response->json('success') !== true || ! is_array($records)
                || ! array_is_list($records) || ! is_int($total) || $total < 0 || $total > 5
                || $responsePage !== $page || ($page > 1 && $pages !== $total)) {
                throw new RuntimeException('Cloudflare zone listing is incomplete or unavailable.');
            }

            $pages = $total;
            foreach ($records as $record) {
                if (! is_string($record['name'] ?? null)) {
                    throw new RuntimeException('Cloudflare zone listing contains an invalid record.');
                }
                $owner = strtolower(rtrim($record['name'], '.'));
                $matchedZone = $matchedZone || $owner === $domain->hostname || str_ends_with($owner, '.'.$domain->hostname);
                if (($record['private_routing'] ?? false) === true) {
                    continue;
                }
                $name = DomainName::normalize($record['name']);
                if ($name !== null && str_ends_with($name, '.'.$domain->hostname)) {
                    $names[$name] = true;
                }
            }
        }

        if (! $matchedZone) {
            throw new RuntimeException('Zone listing does not contain records for the configured hostname.');
        }

        return array_keys($names);
    }
}
