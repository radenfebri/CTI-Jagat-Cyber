<?php

namespace App\Http\Controllers;

use App\Domain\Assets\DomainName;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\PassiveInventory;
use App\Domain\Assets\ZoneFileHostnames;
use App\Domain\Audit\AuditLogger;
use App\Domain\Tenancy\Organization;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

class DomainNamesController extends Controller
{
    public function __construct(private PassiveInventory $inventory, private AuditLogger $audit) {}

    public function store(Request $request, string $organization, string $domain): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);
        $data = $request->validate(['hostnames' => ['required', 'string', 'max:64000']]);
        $lines = preg_split('/\R/', $data['hostnames']);

        $hostnames = [];
        foreach ($lines as $number => $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $hostname = DomainName::normalize(str_contains($line, '.') ? $line : $line.'.'.$target->hostname);
            if ($hostname === null || ! str_ends_with($hostname, '.'.$target->hostname)) {
                throw ValidationException::withMessages(['hostnames' => 'Baris '.($number + 1).' harus berupa subdomain dalam zona ini, tanpa wildcard, URL, atau nilai TXT.']);
            }
            $hostnames[$hostname] = true;
        }

        if (count($hostnames) > 250 || $hostnames === []) {
            throw ValidationException::withMessages(['hostnames' => 'Masukkan 1 sampai 250 hostname unik.']);
        }

        return $this->save($request, $workspace, $target, array_keys($hostnames), 'manual');
    }

    public function storeZone(Request $request, string $organization, string $domain, ZoneFileHostnames $reader): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);
        abort_if($target->verified_at === null, 409, 'Verifikasi domain terlebih dahulu.');
        $data = $request->validate(['zone_file' => ['required', 'file', 'max:256']]);

        try {
            $hostnames = $reader->read($data['zone_file']->get(), $target->hostname);
        } catch (InvalidArgumentException $exception) {
            throw ValidationException::withMessages(['zone_file' => $exception->getMessage()]);
        }

        return $this->save($request, $workspace, $target, $hostnames, 'zone_file');
    }

    /** @param list<string> $hostnames */
    private function save(Request $request, Organization $workspace, MonitoredDomain $target, array $hostnames, string $source): RedirectResponse
    {
        DB::transaction(function () use ($workspace, $target, $hostnames, $source, $request): void {
            $current = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($target->id);
            abort_unless($current->verified_at !== null, 409, 'Verifikasi domain terlebih dahulu.');
            $this->inventory->recordHostnames($current, $hostnames, $source);
            $this->audit->record($workspace->id, $request->user()->id, 'domain.hostnames_imported', [
                'domain_id' => $current->id, 'count' => count($hostnames), 'source' => $source,
            ], $request->ip());
        });

        return to_route('domains.show', [$workspace, $target, 'assets' => 'subdomains'])->with('status', count($hostnames).' nama disimpan sebagai observasi impor.');
    }
}
