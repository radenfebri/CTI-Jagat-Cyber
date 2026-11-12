<?php

namespace App\Domain\Assets;

use App\Jobs\ScanPortChunk;
use Illuminate\Support\Facades\DB;

final class PortScanDispatcher
{
    public function queue(MonitoredDomain $domain, ?int $requestedBy = null): ?PortScanRun
    {
        return DB::transaction(function () use ($domain, $requestedBy): ?PortScanRun {
            $current = MonitoredDomain::query()->lockForUpdate()->find($domain->id);

            if ($current === null
                || $current->verified_at === null
                || ! $current->hasTlsScope()
                || $current->tls_scope !== TlsCheck::DIRECT
                || $current->tls_approved_ip === null
                || ObservedNetwork::classify($current->tls_approved_ip) !== 'public_unknown') {
                return null;
            }

            return $this->createRun($current, $current->tls_approved_ip, $requestedBy);
        });
    }

    public function queueAutomatic(MonitoredDomain $domain): ?PortScanRun
    {
        return DB::transaction(function () use ($domain): ?PortScanRun {
            $current = MonitoredDomain::query()->lockForUpdate()->find($domain->id);

            if ($current === null || $current->verified_at === null
                || $current->portScanRuns()->whereIn('status', ['queued', 'running'])->exists()
                || $current->portScanRuns()->where('created_at', '>', now()->subHours(config('cti.passive_interval_hours')))->exists()) {
                return null;
            }

            $targetIp = $current->tls_scope === TlsCheck::DIRECT
                ? $current->tls_approved_ip
                : $current->assets()->whereNull('retired_at')->whereIn('record_type', ['A', 'AAAA'])
                    ->orderBy('value')->pluck('value')->first(fn (string $address): bool => ObservedNetwork::classify($address) === 'public_unknown');

            if ($targetIp === null || ObservedNetwork::classify($targetIp) !== 'public_unknown') {
                return null;
            }

            return $this->createRun($current, $targetIp, $current->tls_approved_by);
        });
    }

    private function createRun(MonitoredDomain $domain, string $targetIp, ?int $requestedBy): PortScanRun
    {
        if ($domain->portScanRuns()->whereIn('status', ['queued', 'running'])->exists()) {
            return $domain->portScanRuns()->whereIn('status', ['queued', 'running'])->latest('created_at')->firstOrFail();
        }

        $run = $domain->portScanRuns()->create([
            'requested_by' => $requestedBy,
            'target_ip' => $targetIp,
            'range_start' => 1,
            'range_end' => 65535,
            'total_ports' => 65535,
            'status' => 'queued',
        ]);
        $chunkSize = config('cti.port_scan.chunk_size', 256);

        for ($start = 1; $start <= 65535; $start += $chunkSize) {
            dispatch(new ScanPortChunk($run->id, $start, min(65535, $start + $chunkSize - 1)))->afterCommit();
        }

        return $run;
    }
}
