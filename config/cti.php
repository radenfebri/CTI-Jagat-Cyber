<?php

return [
    'cron_token' => env('CTI_CRON_TOKEN'),
    'domain_limit' => max(1, (int) env('CTI_DOMAIN_LIMIT', 20)),
    'verification_interval_minutes' => max(1, (int) env('CTI_VERIFICATION_INTERVAL_MINUTES', 10)),
    'verification_token_days' => max(1, (int) env('CTI_VERIFICATION_TOKEN_DAYS', 7)),
    'txt_authority' => [
        'zone' => env('CTI_TXT_AUTHORITY_ZONE'),
        'server' => env('CTI_TXT_AUTHORITY_SERVER'),
    ],
    'passive_interval_hours' => max(1, (int) env('CTI_PASSIVE_INTERVAL_HOURS', 24)),
    'certspotter_token' => env('CTI_CERTSPOTTER_TOKEN'),
    'ct_page_interval_minutes' => min(1440, max(10, (int) env('CTI_CT_PAGE_INTERVAL_MINUTES', 15))),
    'port_scan' => [
        'chunk_size' => 256,
        'connect_timeout_ms' => min(1000, max(50, (int) env('CTI_PORT_SCAN_TIMEOUT_MS', 150))),
    ],
    'python_worker' => [
        'enabled' => filter_var(env('CTI_PYTHON_WORKER_ENABLED', false), FILTER_VALIDATE_BOOL),
        'url' => rtrim((string) env('CTI_PYTHON_WORKER_URL', 'http://127.0.0.1:9100'), '/'),
        'token' => env('CTI_PYTHON_WORKER_TOKEN'),
        'connect_timeout' => max(1, (int) env('CTI_PYTHON_WORKER_CONNECT_TIMEOUT', 3)),
        'timeout' => max(5, (int) env('CTI_PYTHON_WORKER_TIMEOUT', 60)),
    ],
];
