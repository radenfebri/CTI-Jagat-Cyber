<?php

use App\Http\Controllers\AssetInventoryController;
use App\Http\Controllers\AssetManagementController;
use App\Http\Controllers\AttackSurfaceController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\CloudflareConnectionController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\DomainMonitoringController;
use App\Http\Controllers\DomainNamesController;
use App\Http\Controllers\MonitoredDomainController;
use App\Http\Controllers\OrganizationController;
use App\Http\Controllers\WebMonitoringController;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => auth()->check() ? to_route('dashboard') : view('auth'))->name('home');

Route::middleware('guest')->group(function (): void {
    Route::view('/login', 'auth')->name('login');
    Route::view('/register', 'auth', ['register' => true])->name('register');
    Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:login')->name('login.store');
    Route::post('/register', [AuthController::class, 'register'])->middleware('throttle:register')->name('register.store');
});

Route::middleware('auth')->group(function (): void {
    Route::get('/organizations/{organization}/assets/inventory', AssetInventoryController::class)->whereUuid('organization')->name('assets.inventory');
    Route::get('/organizations/{organization}/attack-surface/vulnerabilities', [AttackSurfaceController::class, 'vulnerabilities'])->whereUuid('organization')->name('attack-surface.vulnerabilities');
    Route::get('/organizations/{organization}/attack-surface/vulnerabilities/{domain}', [AttackSurfaceController::class, 'vulnerabilityDetail'])->whereUuid(['organization', 'domain'])->name('attack-surface.vulnerabilities.detail');
    Route::post('/organizations/{organization}/attack-surface/vulnerabilities/{domain}/port-scans', [AttackSurfaceController::class, 'startPortScan'])->whereUuid(['organization', 'domain'])->middleware('throttle:2,1,cti-port-scans')->name('attack-surface.port-scans.store');
    Route::get('/organizations/{organization}/attack-surface', [AttackSurfaceController::class, 'index'])->whereUuid('organization')->name('attack-surface');
    Route::get('/organizations/{organization}/attack-surface/{domain}/tls', [AttackSurfaceController::class, 'show'])->whereUuid(['organization', 'domain'])->name('attack-surface.tls');
    Route::get('/dashboard', DashboardController::class)->name('dashboard');
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::post('/api/v1/organizations', [OrganizationController::class, 'store'])->name('organizations.store');

    Route::prefix('/organizations/{organization}/domains')->whereUuid('organization')->name('domains.')->group(function (): void {
        Route::get('/', [MonitoredDomainController::class, 'index'])->name('index');
        Route::get('/{domain}', [MonitoredDomainController::class, 'show'])->whereUuid('domain')->name('show');

        Route::middleware('throttle:12,1,cti-domains')->group(function (): void {
            Route::post('/', [MonitoredDomainController::class, 'store'])->name('store');
            Route::delete('/{domain}', [MonitoredDomainController::class, 'destroy'])->whereUuid('domain')->name('destroy');
            Route::delete('/{domain}/assets/{asset}', [AssetManagementController::class, 'destroy'])->whereUuid(['domain', 'asset'])->name('assets.destroy');
            Route::post('/{domain}/challenge', [MonitoredDomainController::class, 'rotateToken'])->whereUuid('domain')->name('challenge');
            Route::post('/{domain}/verify', [MonitoredDomainController::class, 'verify'])->whereUuid('domain')->name('verify');
            Route::post('/{domain}/scope', [MonitoredDomainController::class, 'approve'])->whereUuid('domain')->name('approve');
            Route::delete('/{domain}/scope', [MonitoredDomainController::class, 'revoke'])->whereUuid('domain')->name('revoke');
            Route::post('/{domain}/discovery', [MonitoredDomainController::class, 'discover'])->whereUuid('domain')->name('discover');
            Route::post('/{domain}/certificates', [DomainMonitoringController::class, 'configureCt'])->whereUuid('domain')->name('certificates');
            Route::patch('/{domain}/web-monitoring', [WebMonitoringController::class, 'update'])->whereUuid('domain')->name('web.update');
            Route::post('/{domain}/hostnames', [DomainNamesController::class, 'store'])->whereUuid('domain')->name('hostnames.store');
            Route::post('/{domain}/zone-file', [DomainNamesController::class, 'storeZone'])->whereUuid('domain')->name('zone-file.store');
            Route::patch('/{domain}/cloudflare', [CloudflareConnectionController::class, 'update'])->whereUuid('domain')->name('cloudflare.update');
            Route::post('/{domain}/tls-scope', [DomainMonitoringController::class, 'approveTls'])->whereUuid('domain')->name('tls.approve');
            Route::delete('/{domain}/tls-scope', [DomainMonitoringController::class, 'revokeTls'])->whereUuid('domain')->name('tls.revoke');
            Route::post('/{domain}/tls-checks', [DomainMonitoringController::class, 'queueTls'])->whereUuid('domain')->name('tls.queue');
        });
    });
});
