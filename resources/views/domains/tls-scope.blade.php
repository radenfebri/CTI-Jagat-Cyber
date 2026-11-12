<section id="tls" class="cti-panel min-w-0 p-5">
    <p class="cti-eyebrow text-signal">Authorized Monitoring</p>
    <h2 class="mt-2 text-base font-bold">TLS Certificate · Port 443</h2>
    <p class="mt-2 text-xs leading-5 text-muted">Inspect the certificate exposed through a WAF or CDN, or use a directly managed IP address. Each check records the protocol, issuer, and certificate lifetime.</p>

    @if ($monitoredDomain->hasTlsScope())
        @if ($monitoredDomain->tls_scope === \App\Domain\Assets\TlsCheck::PUBLIC_ENDPOINT)
            <p class="mt-3 text-xs text-muted">The public endpoint is approved. The worker resolves the latest DNS records before each check.</p>
        @else
            <p class="mt-3 text-xs text-muted">Approved direct IP: <code>{{ $monitoredDomain->tls_approved_ip }}</code></p>
        @endif
        <p class="mt-3 text-xs leading-5 text-muted">Public endpoint TLS checks run automatically through the worker.</p>
    @elseif ($canManage && $workspace->allowsDiscovery())
        <p class="mt-3 text-xs text-muted">Public endpoint TLS checks will be enabled automatically by the scheduler.</p>
    @elseif ($canManage)
        <p class="mt-3 text-xs text-muted">TLS checks are available while the organization subscription is active.</p>
    @else
        <p class="mt-3 text-xs text-muted">TLS permissions are managed by organization owners and administrators.</p>
    @endif

    @if ($canManage && $workspace->allowsDiscovery())
        <div class="mt-4 rounded-xl border border-line bg-canvas p-4">
            <h3 class="text-sm font-semibold">Origin Port Scan</h3>
            <p class="mt-1 text-xs leading-5 text-muted">Select a directly managed server IP. Once approved, CTI scans TCP ports 1–65535 automatically. Do not select a Cloudflare or WAF address.</p>
            @if ($monitoredDomain->tls_scope === \App\Domain\Assets\TlsCheck::DIRECT)
                <p class="mt-3 text-xs text-signal">Active direct IP: <code>{{ $monitoredDomain->tls_approved_ip }}</code>. Scans run automatically through the worker.</p>
            @elseif ($tlsCandidates->isNotEmpty())
                <form method="post" action="{{ route('domains.tls.approve', [$workspace, $monitoredDomain]) }}" class="mt-3 grid gap-2.5 sm:max-w-xl">
                    @csrf
                    <input type="hidden" name="scope" value="direct">
                    <label for="tls-direct-ip" class="text-xs font-semibold">Origin IP</label>
                    <select id="tls-direct-ip" name="ip_address" class="cti-field" required>
                        <option value="">Select a detected A/AAAA address</option>
                        @foreach ($tlsCandidates as $candidate)
                            <option value="{{ $candidate }}">{{ $candidate }}</option>
                        @endforeach
                    </select>
                    <label class="flex items-start gap-2 text-xs leading-5 text-muted">
                        <input type="checkbox" name="consent" value="1" required class="mt-0.5 size-4 shrink-0 accent-signal">
                        I am authorized to scan this IP and understand that a TCP 1–65535 scan will run.
                    </label>
                    <button class="cti-primary justify-self-start"><x-cti-icon name="activity" class="size-4"/> Approve IP</button>
                </form>
            @else
                <p class="mt-3 text-xs text-amber-100">No direct public A/AAAA address was detected. For a domain behind Cloudflare or another WAF, add the origin IP to the asset inventory first.</p>
            @endif
        </div>
    @endif

    <div class="mt-4 border-t border-line pt-4">
        <h3 class="text-sm font-semibold">Recent Checks</h3>
        <ul class="mt-2 divide-y divide-line">
            @forelse ($tlsChecks as $check)
                <li class="grid gap-1 py-2.5 text-xs">
                    <div class="flex flex-wrap justify-between gap-2">
                        <span class="font-semibold">{{ $statusLabels[$check->status] ?? $check->status }} · {{ $check->scopeLabel() }} @if ($check->ip_address) · {{ $check->ip_address }} @endif</span>
                        <span class="text-muted">{{ $formatTime($check->created_at) }}</span>
                    </div>
                    @if ($check->result)
                        <span class="text-muted">{{ $check->result['protocol'] ?? 'TLS' }} · {{ $check->result['issuer'] ?? 'Issuer unavailable' }} · Valid until {{ $formatTime(\Illuminate\Support\Carbon::createFromTimestamp($check->result['expires_at'], 'UTC')) }}</span>
                    @elseif ($check->reason)
                        <span class="text-muted">{{ match ($check->reason) {
                            'scope_or_queue_expired' => 'The permission or queued job expired.',
                            'dns_proof_missing' => 'DNS scope evidence is unavailable.',
                            'dns_ip_mismatch' => 'The approved IP no longer matches DNS, or the hostname uses an alias.',
                            'dns_public_endpoint_missing' => 'DNS did not return a scannable public address.',
                            'dns_lookup_failed' => 'The DNS resolver could not resolve an address.',
                            'tls_handshake_failed' => 'The connection or certificate validation failed.',
                            default => 'The worker could not complete the check.',
                        } }}</span>
                    @endif
                </li>
            @empty
                <li class="py-2.5 text-xs text-muted">No TLS checks are available yet.</li>
            @endforelse
        </ul>
    </div>
</section>
