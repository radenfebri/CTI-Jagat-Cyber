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
            $run->forceFill(['status' => 'cancelled', 'finished_at' => now(), 'last_error' => 'Scope tidak lagi disetujui.'])->save();

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
                fclose($socket);
                $open[] = [
                    'port' => $port,
                    'protocol' => 'tcp',
                    'state' => 'open',
                    'latency_ms' => min(65535, (int) round((microtime(true) - $started) * 1000)),
                    'service' => $this->serviceName($port),
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
                    'observed_at' => $result['observed_at'],
                    'created_at' => $timestamp,
                    'updated_at' => $timestamp,
                ], $open);
                PortScanResult::query()->upsert($rows, ['port_scan_run_id', 'port', 'protocol'], ['state', 'latency_ms', 'service', 'observed_at', 'updated_at']);
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

        return $domain instanceof MonitoredDomain
            && $domain->verified_at !== null
            && $domain->hasTlsScope()
            && $domain->tls_scope === 'direct'
            && $domain->tls_approved_ip === $run->target_ip
            && ObservedNetwork::classify($run->target_ip) === 'public_unknown';
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
}
