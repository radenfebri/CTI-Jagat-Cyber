<?php

namespace App\Http\Controllers;

use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\WebObservation;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;

class AssetInventoryController extends Controller
{
    public function __invoke(Request $request, string $organization): View
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $inventory = WebObservation::query()->responded()->whereHas('monitoredDomain', fn (Builder $query) => $query
            ->where('organization_id', $workspace->id)->whereNotNull('verified_at')
            ->whereColumn('monitored_domains.web_authorization_id', 'web_observations.authorization_id'));
        $visible = (clone $inventory)->listedSubdomains();
        $summary = [
            'domains' => (clone $visible)->distinct()->count('monitored_domain_id'),
            'subdomains' => (clone $visible)->distinct()->count('hostname'),
            'addresses' => (clone $visible)->distinct()->count('public_ip'),
        ];

        $search = $request->query('q');
        $search = is_string($search) ? mb_substr(trim($search), 0, 100) : '';
        if ($search !== '') {
            $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            $ip = ObservedNetwork::normalize($search);
            $inventory->where(fn (Builder $query) => $query
                ->whereRaw("hostname LIKE ? ESCAPE '!'", [$pattern])
                ->when($ip !== null, fn (Builder $query) => $query->orWhere('public_ip', $ip)));
        }

        $assets = $inventory->listedSubdomains()->with('monitoredDomain:id,hostname')
            ->orderBy('hostname')->orderBy('id')->paginate(20)
            ->appends(['q' => $search]);

        return view('domains.inventory', compact('workspace', 'summary', 'assets', 'search'));
    }
}
