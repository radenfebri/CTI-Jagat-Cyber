<?php

namespace App\Http\Controllers;

use App\Domain\Tenancy\CreateOrganization;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class OrganizationController extends Controller
{
    public function store(Request $request, CreateOrganization $createOrganization): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'slug' => ['required', 'string', 'alpha_dash', 'max:120', 'unique:organizations,slug'],
        ]);

        try {
            $organization = $createOrganization->handle($request->user(), $data['name'], $data['slug'], $request->ip());
        } catch (UniqueConstraintViolationException) {
            throw ValidationException::withMessages(['slug' => __('validation.unique', ['attribute' => 'slug'])]);
        }

        return response()->json($organization, 201);
    }
}
