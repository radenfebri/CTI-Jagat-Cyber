@php
    $isHidden = $asset->hidden_at !== null;
    $target = [$workspace, $asset->monitored_domain_id, $asset];
    $dialogId = 'asset-actions-'.$asset->id;
@endphp

<button type="button" data-asset-dialog-open aria-haspopup="dialog" aria-controls="{{ $dialogId }}" aria-label="Kelola {{ $asset->value }}"
    class="inline-flex min-h-10 min-w-10 items-center justify-center gap-1.5 rounded-lg border border-line bg-panel px-2.5 text-xs font-semibold text-muted transition-colors hover:border-signal/35 hover:bg-raised hover:text-ink">
    <x-cti-icon name="settings" class="size-4"/>
    <span class="hidden sm:inline">Kelola</span>
</button>

<dialog id="{{ $dialogId }}" aria-labelledby="{{ $dialogId }}-title" aria-describedby="{{ $dialogId }}-host"
    class="fixed inset-x-0 bottom-0 top-auto m-0 max-h-[85dvh] w-full max-w-none overflow-y-auto overscroll-contain rounded-t-3xl border border-line bg-panel text-left text-ink shadow-2xl backdrop:bg-slate-950/65 backdrop:backdrop-blur-sm sm:inset-0 sm:m-auto sm:w-[calc(100%-2rem)] sm:max-w-md sm:rounded-2xl">
    <header class="flex items-start gap-3 border-b border-line p-5 sm:p-6">
        <span class="grid size-10 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon name="settings"/></span>
        <div class="min-w-0 flex-1">
            <h3 id="{{ $dialogId }}-title" class="font-semibold">Kelola subdomain</h3>
            <p id="{{ $dialogId }}-host" class="mt-0.5 text-sm wrap-anywhere text-muted">{{ $asset->value }}</p>
        </div>
        <form method="dialog">
            <button type="submit" autofocus aria-label="Tutup dialog" class="grid size-9 place-items-center rounded-lg text-muted transition-colors hover:bg-raised hover:text-ink">
                <x-cti-icon name="close" class="size-4"/>
            </button>
        </form>
    </header>

    <div class="grid gap-3 p-5 sm:p-6">
        <form method="post" action="{{ route('domains.assets.visibility', $target) }}">
            @csrf
            @method('PATCH')
            <input type="hidden" name="hidden" value="{{ $isHidden ? '0' : '1' }}">
            <input type="hidden" name="from_inventory" value="{{ $fromInventory ? '1' : '0' }}">
            <input type="hidden" name="from_hidden" value="{{ $isHidden ? '1' : '0' }}">
            <button type="submit" class="flex w-full items-center gap-3 rounded-xl border border-line bg-canvas p-3 text-left transition-colors hover:border-signal/35 hover:bg-raised">
                <span class="grid size-9 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon :name="$isHidden ? 'eye' : 'eye-off'" class="size-4"/></span>
                <span class="grid min-w-0 flex-1 gap-0.5">
                    <span class="text-sm font-semibold">{{ $isHidden ? 'Pulihkan observasi' : 'Sembunyikan observasi' }}</span>
                    <span class="text-xs leading-5 text-muted">{{ $isHidden ? 'Tampilkan kembali di inventaris web.' : 'Pindahkan observasi ini ke filter Disembunyikan.' }}</span>
                </span>
                <x-cti-icon name="chevron" class="size-3.5 text-muted"/>
            </button>
        </form>

        @if ($asset->isImported())
            <details class="group rounded-xl border border-line">
                <summary class="flex list-none items-center gap-3 rounded-xl p-3 transition-colors hover:bg-raised [&::-webkit-details-marker]:hidden">
                    <span class="grid size-9 shrink-0 place-items-center rounded-lg bg-red-500/10 text-red-500"><x-cti-icon name="trash" class="size-4"/></span>
                    <span class="flex-1 text-sm font-semibold">Hapus impor</span>
                    <x-cti-icon name="chevron" class="size-3.5 text-muted transition-transform group-open:rotate-90"/>
                </summary>
                <form method="post" action="{{ route('domains.assets.destroy', $target) }}" class="grid gap-3 border-t border-line px-3 pt-3 pb-4">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="from_inventory" value="{{ $fromInventory ? '1' : '0' }}">
                    <input type="hidden" name="from_hidden" value="{{ $isHidden ? '1' : '0' }}">
                    <p class="text-xs leading-5 text-muted">Observasi dari sumber {{ $asset->subdomainSourceLabel() }} akan dihapus permanen.</p>
                    <label class="flex items-start gap-2 text-sm">
                        <input type="checkbox" name="confirm_asset" value="1" class="mt-0.5 size-4 shrink-0 accent-red-500" required> Konfirmasi penghapusan
                    </label>
                    <button type="submit" class="inline-flex min-h-10 items-center gap-2 justify-self-start rounded-lg border border-red-500/45 px-3 text-sm font-semibold transition-colors hover:bg-red-500/10">
                        <x-cti-icon name="trash" class="size-4"/> Hapus permanen
                    </button>
                </form>
            </details>
        @endif
    </div>
</dialog>
