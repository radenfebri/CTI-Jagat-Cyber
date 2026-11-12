<?php

namespace App\Jobs;

use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\PortScanResult;
use App\Domain\Assets\PortScanRun;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ScanPortChunk implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 60;

    public int $tries = 1;

    public int $uniqueFor = 86400;

    public function __construct(public string $runId, public int $startPort, public int $endPort)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return $this->runId.':'.$this->startPort;
    }

    public function handle(): void
    {
        $run = PortScanRun::query()->with('monitoredDomain')->find($this->runId);
        if ($run === null || ! in_array($run->status, ['queued', 'running'], true)) {
            return;
        }

        if (! $this->scopeIsActive($run)) {
            $run->forceFill(['status' => 'cancelled', 'finished_at' => now(), 'last_error' => 'The scan scope is no longer approved.'])->save();

            return;
        }

        $run->newQuery()->whereKey($run->id)->where('status', 'queued')->update(['status' => 'running', 'started_at' => now()]);
        $open = [];
        $timeout = config('cti.port_scan.connect_timeout_ms', 150) / 1000;

        for ($port = $this->startPort; $port <= $this->endPort; $port++) {
            if (! $this->runIsActive()) {
                return;
            }

            $started = microtime(true);
            $socket = @stream_socket_client($this->endpoint($run->target_ip, $port), $errorCode, $errorMessage, $timeout, STREAM_CLIENT_CONNECT);
            if (is_resource($socket)) {
                $metadata = $this->fingerprint($socket, $port, $run->monitoredDomain?->hostname);
                fclose($socket);
                $open[] = [
                    'port' => $port,
                    'protocol' => 'tcp',
                    'state' => 'open',
                    'latency_ms' => min(65535, (int) round((microtime(true) - $started) * 1000)),
                    'service' => $metadata['service'] ?? $this->serviceName($port),
                    'product' => $metadata['product'] ?? null,
                    'service_version' => $metadata['version'] ?? null,
                    'cpe' => $metadata['cpe'] ?? null,
                    'banner' => $metadata['banner'] ?? null,
                    'fingerprint_source' => $metadata['source'] ?? null,
                    'observed_at' => now(),
                ];
            }
        }

        DB::transaction(function () use ($open): void {
            $run = PortScanRun::query()->lockForUpdate()->find($this->runId);
            if ($run === null || ! in_array($run->status, ['queued', 'running'], true)) {
                return;
            }

            if ($open !== []) {
                $timestamp = now();
                $rows = array_map(fn (array $result): array => [
                    'id' => (string) Str::uuid(),
                    'port_scan_run_id' => $run->id,
                    'port' => $result['port'],
                    'protocol' => $result['protocol'],
                    'state' => $result['state'],
                    'latency_ms' => $result['latency_ms'],
                    'service' => $result['service'],
                    'product' => $result['product'],
                    'service_version' => $result['service_version'],
                    'cpe' => $result['cpe'],
                    'banner' => $result['banner'],
                    'fingerprint_source' => $result['fingerprint_source'],
                    'observed_at' => $result['observed_at'],
                    'created_at' => $timestamp,
                    'updated_at' => $timestamp,
                ], $open);
                PortScanResult::query()->upsert($rows, ['port_scan_run_id', 'port', 'protocol'], [
                    'state', 'latency_ms', 'service', 'product', 'service_version', 'cpe', 'banner',
                    'fingerprint_source', 'observed_at', 'updated_at',
                ]);
            }
            $completed = min($run->total_ports, $run->completed_ports + ($this->endPort - $this->startPort + 1));
            $openPorts = $run->results()->where('state', 'open')->count();
            $done = $completed >= $run->total_ports;
            $run->forceFill([
                'completed_ports' => $completed,
                'open_ports' => $openPorts,
                'status' => $done ? 'completed' : 'running',
                'finished_at' => $done ? now() : null,
            ])->save();
        });

        if ((bool) config('cve.enabled')) {
            PortScanResult::query()->where('port_scan_run_id', $this->runId)->whereNotNull('cpe')->pluck('id')
                ->each(fn (string $resultId): mixed => MapPortCves::dispatch($resultId)->afterCommit());
        }
    }

    public function failed(?\Throwable $exception): void
    {
        PortScanRun::query()->whereKey($this->runId)->whereIn('status', ['queued', 'running'])->update([
            'status' => 'failed',
            'last_error' => $exception?->getMessage() ?? 'Port scan worker error.',
            'finished_at' => now(),
        ]);
    }

    private function scopeIsActive(PortScanRun $run): bool
    {
        $domain = $run->monitoredDomain;

        if (! $domain instanceof MonitoredDomain || $domain->verified_at === null) {
            return false;
        }

        if ($domain->hasTlsScope() && $domain->tls_scope === 'direct') {
            return $domain->tls_approved_ip === $run->target_ip
                && ObservedNetwork::classify($run->target_ip) === 'public_unknown';
        }

        return ObservedNetwork::classify($run->target_ip) === 'public_unknown';
    }

    private function runIsActive(): bool
    {
        return PortScanRun::query()->whereKey($this->runId)->whereIn('status', ['queued', 'running'])->exists();
    }

    private function endpoint(string $ip, int $port): string
    {
        $host = str_contains($ip, ':') ? '['.$ip.']' : $ip;

        return 'tcp://'.$host.':'.$port;
    }

    private function serviceName(int $port): ?string
    {
        return match ($port) {
            21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
            80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS',
            445 => 'SMB', 587 => 'SMTP submission', 993 => 'IMAPS', 995 => 'POP3S',
            1433 => 'MSSQL', 1521 => 'Oracle', 3306 => 'MySQL', 3389 => 'RDP',
            5432 => 'PostgreSQL', 6379 => 'Redis', 8080 => 'HTTP alternate', 8443 => 'HTTPS alternate',
            default => null,
        };
    }

    /** @return array{service?: string, product?: string, version?: string, cpe?: string, banner?: string, source?: string} */
    private function fingerprint($socket, int $port, ?string $hostname): array
    {
        stream_set_timeout($socket, 1);
        $request = null;
        if (in_array($port, [80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888], true)) {
            $request = "HEAD / HTTP/1.0\r\nHost: ".($hostname ?: 'localhost')."\r\nUser-Agent: CTI-Jagat-Cyber/1.0\r\nConnection: close\r\n\r\n";
        }
        if ($request !== null) {
            @fwrite($socket, $request);
        }
        $raw = @fread($socket, 4096) ?: '';
        $banner = trim((string) preg_replace('/\s+/', ' ', substr($raw, 0, 512)));
        if ($banner === '') {
            return [];
        }

        $detected = $this->detectBanner($raw, $port);
        if ($detected === []) {
            return ['banner' => $banner, 'source' => 'tcp_banner'];
        }

        $detected['banner'] = $banner;
        $detected['source'] = $detected['source'] ?? 'tcp_banner';
        if (isset($detected['product'], $detected['version'])) {
            $mapping = config('cve.technology_cpe.'.strtolower((string) $detected['product']));
            if (is_array($mapping)) {
                $detected['cpe'] = sprintf(
                    'cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*',
                    $mapping['part'], $mapping['vendor'], $mapping['product'], $detected['version'],
                );
            }
        }

        return $detected;
    }

    /** @return array<string, string> */
    private function detectBanner(string $raw, int $port): array
    {
        $patterns = [
            '/SSH-[0-9.]+-OpenSSH[_ -]([0-9][0-9A-Za-z.~-]*)/i' => ['SSH', 'OpenSSH'],
            '/(?:^|\s)(?:220\s+[^\r\n]*?)?(?:vsftpd\s+)([0-9][0-9.]+)/i' => ['FTP', 'vsftpd'],
            '/(?:proftpd|proftpd server)\s+([0-9][0-9.]+)/i' => ['FTP', 'ProFTPD'],
            '/(?:postfix)\s+([0-9][0-9.]+)/i' => ['SMTP', 'Postfix'],
            '/(?:exim)\s+([0-9][0-9.]+)/i' => ['SMTP', 'Exim'],
            '/(?:mariadb|mysql)[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i' => ['MySQL', 'MySQL'],
            '/Server:\s*([^\r\n]+)/i' => ['HTTP', 'HTTP server'],
            '/X-Powered-By:\s*([^\r\n]+)/i' => ['HTTP', 'HTTP runtime'],
        ];

        foreach ($patterns as $pattern => [$service, $product]) {
            if (preg_match($pattern, $raw, $matches) !== 1) {
                continue;
            }
            $value = trim($matches[1]);
            $version = $value;
            if (in_array($product, ['HTTP server', 'HTTP runtime'], true)) {
                if (preg_match('/([0-9][0-9.]+)/', $value, $versionMatch) !== 1) {
                    return ['service' => $service, 'product' => $value];
                }
                $version = $versionMatch[1];
                $product = preg_replace('/[/ ].*$/', '', $value) ?: $product;
            }

            return ['service' => $service, 'product' => $product, 'version' => $version];
        }

        if ($port === 3306 && strlen($raw) > 5 && ord($raw[4]) === 0x0A) {
            $version = trim((string) strtok(substr($raw, 5), "\0"));

            return $version !== '' ? ['service' => 'MySQL', 'product' => 'MySQL', 'version' => $version] : [];
        }

        return [];
    }
}
