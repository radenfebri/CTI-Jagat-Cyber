@php($target = [$workspace, $asset->monitored_domain_id, $asset])

<form method="post" action="{{ route('domains.assets.destroy', $target) }}"
    onsubmit="return confirm('Delete {{ addslashes($asset->value) }} from inventory?')">
    @csrf
    @method('DELETE')
    <input type="hidden" name="confirm_asset" value="1">
    <input type="hidden" name="from_inventory" value="{{ $fromInventory ? '1' : '0' }}">
    <button type="submit" aria-label="Delete {{ $asset->value }}" title="Delete asset"
        class="inline-flex size-8 items-center justify-center rounded-lg border border-red-500/35 text-red-300 transition-colors hover:bg-red-500/10">
        <x-cti-icon name="trash" class="size-3.5"/>
    </button>
</form>
