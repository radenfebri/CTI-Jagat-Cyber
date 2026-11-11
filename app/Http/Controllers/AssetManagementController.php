<?php

namespace App\Http\Controllers;

use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Audit\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class AssetManagementController extends Controller
{
    public function __construct(private AuditLogger $audit) {}

    public function visibility(Request $request, string $organization, string $domain, string $asset): RedirectResponse
    {
        DB::transaction(function () use ($request, $organization, $domain, $asset): void {
            $observation = $this->lockedAsset($request, $organization, $domain, $asset);
            $request->validate(['hidden' => ['required', 'boolean']]);
            $hidden = $request->boolean('hidden');

            $related = DiscoveredAsset::query()
                ->where('monitored_domain_id', $observation->monitored_domain_id)
                ->where('record_type', $observation->record_type)
                ->where('value', $observation->value)
                ->lockForUpdate()
                ->get();

            if ($related->contains(fn (DiscoveredAsset $asset): bool => $hidden !== ($asset->hidden_at !== null))) {
                $hiddenAt = $hidden ? now() : null;
                $related->each(fn (DiscoveredAsset $asset): bool => (bool) $asset->forceFill(['hidden_at' => $hiddenAt])->save());
                $this->record($request, $organization, $observation, $hidden ? 'asset.hidden' : 'asset.restored');
            }
        });

        $hidden = $request->boolean('hidden');

        return $this->backToInventory($request, $organization, $domain)
            ->with('status', $hidden ? 'Observasi disembunyikan.' : 'Observasi dikembalikan ke inventaris.');
    }

    public function destroy(Request $request, string $organization, string $domain, string $asset): RedirectResponse
    {
        DB::transaction(function () use ($request, $organization, $domain, $asset): void {
            $observation = $this->lockedAsset($request, $organization, $domain, $asset);
            abort_unless($observation->isImported(), 409, 'Observasi dari discovery dapat disembunyikan.');
            $request->validate(['confirm_asset' => ['accepted']], ['confirm_asset.accepted' => 'Konfirmasi penghapusan observasi impor terlebih dahulu.']);

            $this->record($request, $organization, $observation, 'asset.deleted');
            $observation->delete();
        });

        return $this->backToInventory($request, $organization, $domain)->with('status', 'Observasi impor dihapus.');
    }

    private function lockedAsset(Request $request, string $organization, string $domain, string $asset): DiscoveredAsset
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($domain);
        Gate::authorize('manage', $target);

        return $target->assets()->lockForUpdate()->findOrFail($asset);
    }

    private function record(Request $request, string $organization, DiscoveredAsset $asset, string $event): void
    {
        $this->audit->record($organization, $request->user()->id, $event, [
            'domain_id' => $asset->monitored_domain_id,
            'asset_id' => $asset->id,
            'type' => $asset->record_type,
            'value' => $asset->value,
            'source' => $asset->source,
        ], $request->ip());
    }

    private function backToInventory(Request $request, string $organization, string $domain): RedirectResponse
    {
        $hidden = $request->boolean('from_hidden');

        if ($request->boolean('from_inventory')) {
            return to_route('assets.inventory', ['organization' => $organization, 'state' => $hidden ? 'hidden' : 'all']);
        }

        return redirect()->to(route('domains.show', [$organization, $domain, 'assets' => $hidden ? 'hidden' : 'all']).'#inventaris');
    }
}
