<?php

namespace App\Domain\Assets;

interface TlsProbe
{
    /** @return array{protocol: ?string, issuer: ?string, expires_at: int, fingerprint_sha256: string} */
    public function inspect(string $hostname, string $approvedIp): array;
}
