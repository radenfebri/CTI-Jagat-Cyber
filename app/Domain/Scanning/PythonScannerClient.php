<?php

namespace App\Domain\Scanning;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RuntimeException;

final class PythonScannerClient
{
    public function enabled(): bool
    {
        return (bool) config('cti.python_worker.enabled')
            && filled(config('cti.python_worker.url'))
            && filled(config('cti.python_worker.token'));
    }

    /** @return array<string, mixed> */
    public function fingerprint(string $hostname, string $baseDomain): array
    {
        if (! $this->enabled()) {
            return [];
        }

        $response = $this->request()
            ->retry([250, 1000], 2, fn (\Throwable $exception): bool => $exception instanceof ConnectionException)
            ->post('/v1/fingerprint', [
                'hostname' => $hostname,
                'base_domain' => $baseDomain,
            ])
            ->throw();

        $payload = $response->json();
        if (! is_array($payload) || ! is_string($payload['hostname'] ?? null)) {
            throw new RuntimeException('Python worker returned an invalid fingerprint payload.');
        }

        return $payload;
    }

    public function health(): bool
    {
        if (! $this->enabled()) {
            return false;
        }

        try {
            return $this->request()->get('/health')->successful();
        } catch (\Throwable) {
            return false;
        }
    }

    private function request(): PendingRequest
    {
        return Http::baseUrl((string) config('cti.python_worker.url'))
            ->withToken((string) config('cti.python_worker.token'))
            ->acceptJson()
            ->connectTimeout((int) config('cti.python_worker.connect_timeout'))
            ->timeout((int) config('cti.python_worker.timeout'));
    }
}
