<?php

namespace App\Domain\Assets;

final class NativeWebProbe implements WebProbe
{
    public function inspect(string $hostname, string $publicIp): ?array
    {
        if (DomainName::normalize($hostname) !== $hostname || ! ObservedNetwork::isPublic($publicIp)) {
            return null;
        }

        $address = str_contains($publicIp, ':') ? '['.$publicIp.']' : $publicIp;
        foreach (['https' => 443, 'http' => 80] as $scheme => $port) {
            $curl = curl_init($scheme.'://'.$hostname.'/');
            $headers = [];
            $body = '';
            if ($curl === false || ! curl_setopt_array($curl, [
                CURLOPT_RESOLVE => [$hostname.':'.$port.':'.$address],
                CURLOPT_PROXY => '',
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT_MS => 2000,
                CURLOPT_TIMEOUT_MS => 4000,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => 'CTI-Jagat-Cyber/1.0',
                CURLOPT_ENCODING => '',
                CURLOPT_HEADERFUNCTION => function ($handle, string $line) use (&$headers): int {
                    $length = strlen($line);
                    $line = trim($line);
                    if (str_contains($line, ':')) {
                        [$name, $value] = explode(':', $line, 2);
                        $key = mb_strtolower(trim($name));
                        $headers[$key] = isset($headers[$key]) ? $headers[$key]."\n".trim($value) : trim($value);
                    }

                    return $length;
                },
                CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body): int {
                    $limit = 131072;
                    if (strlen($body) < $limit) {
                        $body .= substr($chunk, 0, $limit - strlen($body));
                    }

                    return strlen($chunk);
                },
            ])) {
                return null;
            }
            $completed = curl_exec($curl) !== false;
            $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            $primaryIp = ObservedNetwork::normalize(curl_getinfo($curl, CURLINFO_PRIMARY_IP));
            curl_close($curl);
            if ($completed && $status >= 100 && $status <= 599 && $primaryIp === $publicIp) {
                return [
                    'scheme' => $scheme,
                    'status_code' => $status,
                    'server_header' => isset($headers['server']) ? mb_substr($headers['server'], 0, 255) : null,
                    'technologies' => $this->fingerprint($headers, $body),
                ];
            }
        }

        return null;
    }

    /** @return list<array{name: string, version: string|null, source: string}> */
    private function fingerprint(array $headers, string $body): array
    {
        $facts = [];
        $add = function (string $name, ?string $version, string $source) use (&$facts): void {
            $key = mb_strtolower($name.'|'.($version ?? ''));
            foreach ($facts as $fact) {
                if (mb_strtolower($fact['name'].'|'.($fact['version'] ?? '')) === $key) {
                    return;
                }
            }
            $facts[] = ['name' => $name, 'version' => $version, 'source' => $source];
        };

        $server = $headers['server'] ?? '';
        if (preg_match('/\b(cloudflare)\b/i', $server) || isset($headers['cf-ray'])) {
            $add('Cloudflare', null, 'header');
        }
        if (preg_match('/\b(apache|nginx|caddy|microsoft-iis)(?:\/([\d.]+))?/i', $server, $match)) {
            $add($match[1], $match[2] ?? null, 'header');
        }

        $powered = $headers['x-powered-by'] ?? '';
        if (preg_match('/\bphp\/?([\d.]+)?/i', $powered, $match)) {
            $add('PHP', $match[1] ?? null, 'header');
        }
        if (preg_match('/\bexpress\/?([\d.]+)?/i', $powered, $match)) {
            $add('Express', $match[1] ?? null, 'header');
        }
        if (preg_match('/\bwordpress\/?([\d.]+)?/i', $headers['x-generator'] ?? '', $match)) {
            $add('WordPress', $match[1] ?? null, 'header');
        }
        if (str_contains(mb_strtolower($headers['set-cookie'] ?? ''), 'laravel_session')) {
            $add('Laravel', null, 'cookie');
        }

        $lowerBody = mb_strtolower($body);
        if (str_contains($lowerBody, 'wp-content/') || str_contains($lowerBody, 'wp-includes/')) {
            $add('WordPress', null, 'body');
        }
        if (preg_match('/bootstrap@([\d]+\.[\d]+(?:\.[\d]+)?)/i', $body, $match)
            || preg_match('/bootstrap(?:\.min)?\.(?:css|js)[^\d]{0,30}([\d]+\.[\d]+(?:\.[\d]+)?)/i', $body, $match)) {
            $add('Bootstrap', $match[1], 'body');
        } elseif (str_contains($lowerBody, 'bootstrap')) {
            $add('Bootstrap', null, 'body');
        }
        if (preg_match('/jquery@([\d]+\.[\d]+(?:\.[\d]+)?)/i', $body, $match)) {
            $add('jQuery', $match[1], 'body');
        } elseif (preg_match('/jquery(?:\.min)?\.js/i', $body)) {
            $add('jQuery', null, 'body');
        }
        foreach ([
            'React' => '/(?:react(?:\.production)?\.min)?\.js/i',
            'Vue' => '/vue(?:\.global)?(?:\.prod)?\.js/i',
            'Angular' => '/(?:angular|zone)\.min?\.js/i',
        ] as $name => $pattern) {
            if (preg_match($pattern, $body)) {
                $add($name, null, 'body');
            }
        }

        return $facts;
    }
}
