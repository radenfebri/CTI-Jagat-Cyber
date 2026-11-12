<?php

namespace App\Domain\Assets;

interface WebProbe
{
    /** @return array{scheme: string, status_code: int, server_header: string|null, technologies: list<array{name: string, version: string|null, source: string, category?: string}>}|null */
    public function inspect(string $hostname, string $publicIp): ?array;
}
