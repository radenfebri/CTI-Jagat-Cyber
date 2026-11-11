<?php

use App\Http\Controllers\CtiCronController;
use Illuminate\Support\Facades\Route;

Route::get('/cron/cti', CtiCronController::class)->name('cti.cron');
