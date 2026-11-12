<?php

namespace App\Http\Controllers;

use App\Domain\Identity\Membership;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class DashboardController extends Controller
{
    public function __invoke(Request $request): View
    {
        $user = $request->user();
        $organizationId = $request->query('organization');
        abort_unless($organizationId === null || (is_string($organizationId) && Str::isUuid($organizationId)), 404);

        $organizations = $user->organizations()->orderBy('name')->orderBy('organizations.id')->get();
        $organization = $organizations->first();

        if ($organizationId !== null) {
            $organization = $organizations->firstWhere('id', Str::lower($organizationId));
            abort_if($organization === null, 404);
        }

        $memberCount = $organization ? Membership::where('organization_id', $organization->id)->count() : 0;

        return view('dashboard', compact('organizations', 'organization', 'memberCount'));
    }
}
