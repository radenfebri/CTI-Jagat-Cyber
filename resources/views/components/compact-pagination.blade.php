@if ($paginator->hasPages())
    <nav role="navigation" aria-label="Pagination" class="flex min-h-8 items-center justify-between gap-3">
        <p class="truncate text-[0.65rem] text-muted">
            <span class="hidden sm:inline">Showing </span><span class="font-semibold text-ink">{{ $paginator->firstItem() }}–{{ $paginator->lastItem() }}</span>
            of <span class="font-semibold text-ink">{{ $paginator->total() }}</span>
        </p>

        <div class="inline-flex shrink-0 overflow-hidden rounded-lg border border-line bg-canvas">
            @if ($paginator->onFirstPage())
                <span class="grid size-8 cursor-not-allowed place-items-center text-muted opacity-40" aria-disabled="true" aria-label="Previous page">
                    <x-cti-icon name="chevron" class="size-3 -rotate-180"/>
                </span>
            @else
                <a href="{{ $paginator->previousPageUrl() }}" rel="prev" class="grid size-8 place-items-center text-muted transition-colors hover:bg-raised hover:text-ink" aria-label="Previous page">
                    <x-cti-icon name="chevron" class="size-3 -rotate-180"/>
                </a>
            @endif

            @foreach ($elements as $element)
                @if (is_string($element))
                    <span class="grid size-8 place-items-center border-l border-line text-[0.65rem] text-muted" aria-hidden="true">{{ $element }}</span>
                @endif

                @if (is_array($element))
                    @foreach ($element as $page => $url)
                        @if ($page === $paginator->currentPage())
                            <span class="grid size-8 place-items-center border-l border-line bg-raised text-[0.7rem] font-bold text-ink" aria-current="page" aria-label="Current page, page {{ $page }}">{{ $page }}</span>
                        @else
                            <a href="{{ $url }}" class="grid size-8 place-items-center border-l border-line text-[0.7rem] font-semibold text-muted transition-colors hover:bg-raised hover:text-ink" aria-label="Go to page {{ $page }}">{{ $page }}</a>
                        @endif
                    @endforeach
                @endif
            @endforeach

            @if ($paginator->hasMorePages())
                <a href="{{ $paginator->nextPageUrl() }}" rel="next" class="grid size-8 place-items-center border-l border-line text-muted transition-colors hover:bg-raised hover:text-ink" aria-label="Next page">
                    <x-cti-icon name="chevron" class="size-3"/>
                </a>
            @else
                <span class="grid size-8 cursor-not-allowed place-items-center border-l border-line text-muted opacity-40" aria-disabled="true" aria-label="Next page">
                    <x-cti-icon name="chevron" class="size-3"/>
                </span>
            @endif
        </div>
    </nav>
@endif
