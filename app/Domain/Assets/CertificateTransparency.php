<?php

namespace App\Domain\Assets;

use Illuminate\Support\Facades\Http;
use RuntimeException;

final class CertificateTransparency
{
    public const SOURCE = 'certspotter';

    private const ENDPOINT = 'https://api.certspotter.com/v1/issuances';

    private const MAX_BYTES = 1048576;

    /** @return array{cursor: ?string, hosts: list<string>} */
    public function nextPage(string $hostname, ?string $cursor): array
    {
        $query = ['domain' => $hostname, 'include_subdomains' => 'true', 'expand' => 'dns_names'];
        if ($cursor !== null) {
            $query['after'] = $cursor;
        }

        $client = Http::acceptJson()->connectTimeout(3)->timeout(8)->withoutRedirecting()
            ->withOptions(['stream' => true, 'read_timeout' => 3]);
        if (config('cti.certspotter_token')) {
            $client->withToken(config('cti.certspotter_token'));
        }

        $deadline = hrtime(true) + 10000000000;
        $response = $client->get(self::ENDPOINT, $query);
        $body = $response->toPsrResponse()->getBody();
        try {
            if (! $response->successful()) {
                throw new RuntimeException('Certificate Transparency source unavailable.');
            }

            $contents = '';
            while (! $body->eof()) {
                $chunk = $body->read(min(8192, self::MAX_BYTES + 1 - strlen($contents)));
                if (hrtime(true) >= $deadline || ($chunk === '' && ! $body->eof())) {
                    throw new RuntimeException('Certificate Transparency response timed out.');
                }
                $contents .= $chunk;
                if (strlen($contents) > self::MAX_BYTES) {
                    throw new RuntimeException('Certificate Transparency response is too large.');
                }
            }
        } finally {
            $body->close();
        }

        $issuances = json_decode($contents, true, flags: JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        if (! is_array($issuances) || ! array_is_list($issuances)) {
            throw new RuntimeException('Unexpected Certificate Transparency response.');
        }

        $hosts = [];
        $next = $cursor;
        foreach ($issuances as $issuance) {
            $id = $issuance['id'] ?? null;
            if ((! is_string($id) && ! is_int($id)) || ! preg_match('/\A[0-9]{1,64}\z/', (string) $id)
                || ! is_array($issuance['dns_names'] ?? null)) {
                throw new RuntimeException('Invalid Certificate Transparency issuance.');
            }
            $next = (string) $id;
            foreach ($issuance['dns_names'] as $name) {
                $name = is_string($name) ? DomainName::normalize($name) : null;
                if ($name !== null && str_ends_with($name, '.'.$hostname)) {
                    $hosts[$name] = true;
                }
            }
        }

        return ['cursor' => $next, 'hosts' => array_keys($hosts)];
    }
}
