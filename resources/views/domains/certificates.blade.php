<section class="cti-panel min-w-0 p-5">
    <p class="cti-eyebrow text-signal">Subdomain Discovery</p>
    <h2 class="mt-2 text-base font-bold">Certificate Transparency</h2>
    <p class="mt-2 text-xs leading-5 text-muted">Cert Spotter finds subdomains from public certificates and adds them to the asset inventory.</p>
    @if ($monitoredDomain->ct_authorization_id)
        <p class="mt-3 text-xs text-muted">{{ match ($monitoredDomain->ct_status) {
            'complete' => 'Checked. The source has no new pages.',
            'page_saved' => 'One page was saved. The worker will continue automatically.',
            'unavailable' => 'The source is temporarily unavailable. DNS discovery continues.',
            default => 'Active. Waiting for the next passive discovery run.',
        } }}</p>
    @elseif ($active && $workspace->allowsDiscovery())
        <p class="mt-3 text-xs text-muted">Public certificate discovery will be enabled automatically by the scheduler.</p>
    @else
        <p class="mt-3 text-xs text-muted">Public certificate discovery will be enabled automatically when discovery runs.</p>
    @endif
</section>
