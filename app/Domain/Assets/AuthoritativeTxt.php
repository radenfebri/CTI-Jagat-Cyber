<?php

namespace App\Domain\Assets;

use RuntimeException;

class AuthoritativeTxt
{
    private const TXT = 16;

    private const INTERNET = 1;

    public function matches(string $name, string $expected, string $server): bool
    {
        if (! ObservedNetwork::isPublic($server)) {
            throw new RuntimeException('The configured TXT nameserver must be a public IP address.');
        }

        $id = random_int(0, 65535);
        $question = '';
        foreach (explode('.', $name) as $label) {
            if (! preg_match('/\A[a-z0-9_-]{1,63}\z/i', $label)) {
                throw new RuntimeException('Invalid TXT query name.');
            }
            $question .= chr(strlen($label)).$label;
        }
        $question .= "\0".pack('n2', self::TXT, self::INTERNET);
        $reply = $this->exchange($server, pack('n6', $id, 0, 1, 0, 0, 0).$question);

        if (strlen($reply) < 12) {
            throw new RuntimeException('Incomplete DNS response.');
        }

        $header = unpack('nid/nflags/nquestions/nanswers', $reply);
        // Require a standard, complete, authoritative response for this query.
        if ($header['id'] !== $id || ($header['flags'] & 0xFE00) !== 0x8400 || $header['questions'] !== 1) {
            throw new RuntimeException('Unexpected authoritative DNS response.');
        }
        if (strcasecmp(substr($reply, 12, strlen($question)), $question) !== 0) {
            throw new RuntimeException('DNS response question does not match the TXT query.');
        }

        $rcode = $header['flags'] & 0x000F;
        if ($rcode === 3) {
            return false;
        }
        if ($rcode !== 0) {
            throw new RuntimeException('Authoritative TXT lookup failed with DNS code '.$rcode.'.');
        }

        $offset = 12 + strlen($question);
        for ($index = 0; $index < $header['answers']; $index++) {
            $owner = $this->readName($reply, $offset);
            if ($offset + 10 > strlen($reply)) {
                throw new RuntimeException('Incomplete DNS answer header.');
            }
            $record = unpack('ntype/nclass/Nttl/nlength', $reply, $offset);
            $offset += 10;
            $end = $offset + $record['length'];
            if ($end > strlen($reply)) {
                throw new RuntimeException('Incomplete DNS answer data.');
            }

            if ($record['type'] === self::TXT && $record['class'] === self::INTERNET && strcasecmp($owner, $name) === 0) {
                $value = '';
                while ($offset < $end) {
                    $length = ord($reply[$offset++]);
                    if ($offset + $length > $end) {
                        throw new RuntimeException('Invalid TXT answer data.');
                    }
                    $value .= substr($reply, $offset, $length);
                    $offset += $length;
                }
                if (hash_equals($expected, $value)) {
                    return true;
                }
            }
            $offset = $end;
        }

        return false;
    }

    protected function exchange(string $server, string $packet): string
    {
        $target = str_contains($server, ':') ? '['.$server.']' : $server;
        $socket = @stream_socket_client('tcp://'.$target.':53', $errorCode, $errorMessage, 2);
        if ($socket === false) {
            throw new RuntimeException('Could not connect to the configured TXT nameserver.');
        }

        try {
            stream_set_timeout($socket, 2);
            $frame = pack('n', strlen($packet)).$packet;
            if (@fwrite($socket, $frame) !== strlen($frame)) {
                throw new RuntimeException('Could not send the TXT query.');
            }
            $prefix = stream_get_contents($socket, 2);
            if ($prefix === false || strlen($prefix) !== 2) {
                throw new RuntimeException('Could not read the DNS response length.');
            }
            $length = unpack('n', $prefix)[1];
            if ($length < 12 || $length > 4096) {
                throw new RuntimeException('Unexpected DNS response size.');
            }
            $reply = stream_get_contents($socket, $length);
            if ($reply === false || strlen($reply) !== $length) {
                throw new RuntimeException('Could not read the complete DNS response.');
            }

            return $reply;
        } finally {
            fclose($socket);
        }
    }

    private function readName(string $reply, int &$offset): string
    {
        $labels = [];
        $cursor = $offset;
        $pointerFound = false;
        $limit = strlen($reply);

        while ($cursor < $limit && count($labels) < 128) {
            $size = ord($reply[$cursor++]);
            if ($size === 0) {
                if (! $pointerFound) {
                    $offset = $cursor;
                }

                return implode('.', $labels);
            }
            if ($size >= 192 && $cursor < $limit) {
                $pointer = (($size & 63) << 8) | ord($reply[$cursor++]);
                if ($pointer < 12 || $pointer >= $cursor - 2) {
                    break;
                }
                if (! $pointerFound) {
                    $offset = $cursor;
                    $pointerFound = true;
                }
                $limit = $cursor - 2;
                $cursor = $pointer;
            } elseif ($size <= 63 && $cursor + $size <= $limit) {
                $labels[] = substr($reply, $cursor, $size);
                $cursor += $size;
            } else {
                break;
            }
        }

        throw new RuntimeException('Invalid name in DNS response.');
    }
}
