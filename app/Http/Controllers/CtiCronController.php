<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Queue;

class CtiCronController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $expected = config('cti.cron_token');
        $token = $request->query('token');
        if (! is_string($expected) || ! preg_match('/\A[a-f0-9]{64}\z/', $expected)
            || ! is_string($token) || strlen($token) !== 64 || ! hash_equals($expected, $token)) {
            return $this->result('not_found', 404);
        }

        if (! $request->isMethod('GET')) {
            return $this->result('method_not_allowed', 405)->header('Allow', 'GET');
        }

        $connection = config('queue.default');
        if (config('queue.connections.'.$connection.'.driver') !== 'database') {
            return $this->result('database_queue_required', 503);
        }

        $response = Cache::lock('cti:cron-url', 120)->get(function () use ($connection): JsonResponse {
            // Refill only an empty queue so manual jobs and retries can clear first.
            if (Queue::connection($connection)->size('cti') === 0
                && Artisan::call('cti:dispatch-domain-jobs', ['--limit' => 1]) !== 0) {
                return $this->result('dispatch_failed', 503);
            }

            $exitCode = Artisan::call('queue:work', [
                'connection' => $connection,
                '--queue' => 'cti',
                '--once' => true,
                '--sleep' => 0,
                '--no-interaction' => true,
            ]);

            return $exitCode === 0 ? $this->result('tick_completed') : $this->result('worker_failed', 503);
        });

        return $response ?: $this->result('already_running', 202);
    }

    private function result(string $status, int $code = 200): JsonResponse
    {
        return response()->json(['status' => $status], $code, [
            'Cache-Control' => 'no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }
}
