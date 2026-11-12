<?php

namespace App\Domain\Assets;

use InvalidArgumentException;

final class ZoneFileHostnames
{
    private const RECORD_TYPES = [
        'A', 'AAAA', 'CAA', 'CDNSKEY', 'CDS', 'CNAME', 'DNAME', 'DNSKEY', 'DS',
        'HINFO', 'HTTPS', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM',
        'PTR', 'RP', 'RRSIG', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI',
    ];

    /** @return list<string> */
    public function read(string $contents, string $zone): array
    {
        if (str_contains($contents, "\0") || ! mb_check_encoding($contents, 'UTF-8')) {
            throw new InvalidArgumentException('Use a UTF-8 text BIND zone file.');
        }

        $contents = str_starts_with($contents, "\xEF\xBB\xBF") ? substr($contents, 3) : $contents;
        $origin = $zone;
        $previousOwner = null;
        $hostnames = [];

        foreach ($this->entries($contents) as $entry) {
            $tokens = preg_split('/[ \t]+/', trim($entry), 6);
            $head = $tokens[0];

            if (str_starts_with($head, '$')) {
                $value = $tokens[1] ?? '';
                if (count($tokens) === 2 && strcasecmp($head, '$ORIGIN') === 0) {
                    $origin = $value === '.' ? '' : DomainName::normalize($this->absoluteName($value, $origin));
                    if ($origin === null) {
                        throw new InvalidArgumentException('The $ORIGIN name is invalid.');
                    }
                } elseif (count($tokens) !== 2 || strcasecmp($head, '$TTL') !== 0 || ! $this->isTtl($value)) {
                    throw new InvalidArgumentException('Only $ORIGIN and $TTL directives are supported. Export the complete zone without $INCLUDE or $GENERATE.');
                }

                continue;
            }

            $ownerOmitted = $entry[0] === ' ' || $entry[0] === "\t";
            $offset = $ownerOmitted ? 0 : 1;
            $owner = $ownerOmitted ? $previousOwner : $this->absoluteName($head, $origin);
            if ($owner === null) {
                throw new InvalidArgumentException('The first record must include an owner name.');
            }

            $seenTtl = $seenClass = false;
            while (isset($tokens[$offset])) {
                $token = strtoupper($tokens[$offset]);
                if (! $seenTtl && $this->isTtl($token)) {
                    $seenTtl = true;
                } elseif (! $seenClass && $token === 'IN') {
                    $seenClass = true;
                } else {
                    break;
                }
                $offset++;
            }

            $type = strtoupper($tokens[$offset] ?? '');
            if ((! in_array($type, self::RECORD_TYPES, true) && ! preg_match('/^TYPE[0-9]{1,5}$/D', $type)) || ! isset($tokens[$offset + 1])) {
                throw new InvalidArgumentException('The zone contains an unsupported or incomplete record. Use a BIND zone export.');
            }

            $previousOwner = $owner;
            $name = DomainName::normalize($owner);
            if ($name !== null && str_ends_with($name, '.'.$zone)) {
                $hostnames[$name] = true;
                if (count($hostnames) > 1000) {
                    throw new InvalidArgumentException('A file may import up to 1,000 unique names.');
                }
            }
        }

        if ($hostnames === []) {
            throw new InvalidArgumentException('No importable subdomain names were found in this zone.');
        }

        return array_keys($hostnames);
    }

    private function absoluteName(string $name, string $origin): string
    {
        if ($name === '@') {
            return $origin;
        }

        return $origin === '' || str_ends_with($name, '.') ? $name : $name.'.'.$origin;
    }

    private function isTtl(string $token): bool
    {
        return preg_match('/^(?:[0-9]+[smhdw])+[0-9]*$|^[0-9]+$/iD', $token) === 1;
    }

    /** @return iterable<string> */
    private function entries(string $contents): iterable
    {
        $contents = str_replace(["\r\n", "\r"], "\n", $contents);
        $entry = '';
        $quoted = $parenthesized = $comment = false;
        $length = strlen($contents);

        for ($i = 0; $i < $length; $i++) {
            $char = $contents[$i];
            if ($comment && $char !== "\n") {
                continue;
            }
            $comment = false;

            if ($char === '\\' && $i + 1 < $length) {
                $entry .= $char.$contents[++$i];
            } elseif ($char === '"') {
                $quoted = ! $quoted;
                $entry .= $char;
            } elseif (! $quoted && $char === ';') {
                $comment = true;
            } elseif (! $quoted && ($char === '(' || $char === ')')) {
                if ($parenthesized === ($char === '(')) {
                    throw new InvalidArgumentException('The zone file contains unbalanced parentheses.');
                }
                $parenthesized = $char === '(';
                $entry .= ' ';
            } elseif ($char === "\n" && ! $quoted && ! $parenthesized) {
                if (trim($entry) !== '') {
                    yield $entry;
                }
                $entry = '';
            } else {
                $entry .= $char === "\n" ? ' ' : $char;
            }
        }

        if ($quoted || $parenthesized) {
            throw new InvalidArgumentException('The zone file contains an unclosed quote or parenthesis.');
        }
        if (trim($entry) !== '') {
            yield $entry;
        }
    }
}
