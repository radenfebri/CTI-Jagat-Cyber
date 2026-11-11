<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Schedule::command('cti:dispatch-domain-jobs')->everyMinute()->onOneServer()->withoutOverlapping(5);
Schedule::command('cti:dispatch-cve-mapping --limit=1000')->daily()->onOneServer()->withoutOverlapping(30);
