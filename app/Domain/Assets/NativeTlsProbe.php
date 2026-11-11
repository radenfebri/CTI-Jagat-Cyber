<?php

namespace App\Domain\Assets;

use RuntimeException;

final class NativeTlsProbe implements TlsProbe
{
    public function inspect(string $hostname, string $approvedIp): array
    {
        if (DomainName::normalize($hostname) !== $hostname || ! ObservedNetwork::isPublic($approvedIp)) {
            throw new RuntimeException('TLS target outside the supported scope.');
        }

        $target = str_contains($approvedIp, ':') ? '['.$approvedIp.']' : $approvedIp;
        $context = stream_context_create(['ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $hostname,
            'SNI_enabled' => true,
            'capture_peer_cert' => true,
        ]]);

        $socket = @stream_socket_client('tcp://'.$target.':443', $errno, $error, 4, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) {
            throw new RuntimeException('TLS connection failed.');
        }

        try {
            stream_set_timeout($socket, 4);
            $enabled = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            if ($enabled !== true) {
                throw new RuntimeException('TLS certificate or handshake failed validation.');
            }

            $certificate = stream_context_get_options($socket)['ssl']['peer_certificate'] ?? null;
            $fields = $certificate ? openssl_x509_parse($certificate) : false;
            $fingerprint = $certificate ? openssl_x509_fingerprint($certificate, 'sha256') : false;
            if (! is_int($fields['validTo_time_t'] ?? null) || $fingerprint === false) {
                throw new RuntimeException('TLS certificate metadata is missing.');
            }

            $issuer = $fields['issuer']['CN'] ?? null;

            return [
                'protocol' => stream_get_meta_data($socket)['crypto']['protocol'] ?? null,
                'issuer' => is_string($issuer) ? mb_substr($issuer, 0, 200) : null,
                'expires_at' => $fields['validTo_time_t'],
                'fingerprint_sha256' => $fingerprint,
            ];
        } finally {
            fclose($socket);
        }
    }
}
