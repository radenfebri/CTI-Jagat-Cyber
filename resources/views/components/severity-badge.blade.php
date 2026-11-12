@props(['severity' => null, 'score' => null, 'label' => null])

@php
    $normalizedSeverity = is_string($severity) ? strtolower($severity) : null;
    $tone = match ($normalizedSeverity) {
        'critical' => 'border-red-400/30 bg-red-500/15 text-red-200',
        'high' => 'border-orange-400/30 bg-orange-500/15 text-orange-200',
        'medium' => 'border-amber-400/30 bg-amber-500/15 text-amber-100',
        'low' => 'border-sky-400/30 bg-sky-500/15 text-sky-200',
        'none' => 'border-signal/25 bg-signal-bg text-signal',
        default => 'border-line bg-raised text-muted',
    };
    $displayLabel = $label ?? ($normalizedSeverity ? ucfirst($normalizedSeverity) : 'No findings');
@endphp

<span {{ $attributes->class(['inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[0.62rem] font-semibold leading-none', $tone]) }}>
    {{ $displayLabel }}
    @if ($score !== null)
        <span class="font-mono opacity-80">{{ number_format((float) $score, 1) }}</span>
    @endif
</span>
