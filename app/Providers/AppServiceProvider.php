<?php

namespace App\Providers;

use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\NativeTlsProbe;
use App\Domain\Assets\NativeWebProbe;
use App\Domain\Assets\SystemDnsResolver;
use App\Domain\Assets\TlsProbe;
use App\Domain\Assets\WebProbe;
use App\Policies\MonitoredDomainPolicy;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(DnsResolver::class, SystemDnsResolver::class);
        $this->app->bind(TlsProbe::class, NativeTlsProbe::class);
        $this->app->bind(WebProbe::class, NativeWebProbe::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Gate::policy(MonitoredDomain::class, MonitoredDomainPolicy::class);

        RateLimiter::for('login', function (Request $request): array {
            $email = $request->input('email');
            $account = is_string($email) ? Str::lower($email) : '';

            return [
                Limit::perMinute(40)->by('ip:'.$request->ip()),
                Limit::perMinute(5)->by('account:'.$account.'|'.$request->ip()),
            ];
        });

        RateLimiter::for('register', fn (Request $request): Limit => Limit::perMinute(5)->by($request->ip()));
    }
}
