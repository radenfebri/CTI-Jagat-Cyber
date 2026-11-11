<?php

namespace App\Domain\Assets;

final class DomainName
{
    public static function normalize(string $value): ?string
    {
        $hostname = trim($value);
        $hostname = str_ends_with($hostname, '.') ? substr($hostname, 0, -1) : $hostname;

        if (preg_match('/[^\x00-\x7F]/', $hostname)) {
            if (! function_exists('idn_to_ascii')) {
                return null;
            }

            $hostname = idn_to_ascii($hostname, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
        }

        if (! is_string($hostname) || strlen($hostname) > 253 || ! filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return null;
        }

        $hostname = strtolower($hostname);
        $suffix = strrchr($hostname, '.');

        if ($suffix === false || ! preg_match('/^\.(?:[a-z]{2,63}|xn--[a-z0-9-]+)$/', $suffix)) {
            return null;
        }

        if (in_array($suffix, ['.local', '.localhost', '.test', '.invalid', '.example', '.internal', '.home', '.lan', '.onion'], true)) {
            return null;
        }

        return $hostname;
    }
}
