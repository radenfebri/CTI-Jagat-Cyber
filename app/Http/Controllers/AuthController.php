<?php

namespace App\Http\Controllers;

use App\Domain\Tenancy\CreateOrganization;
use App\Models\User;
use Closure;
use Illuminate\Auth\Events\Registered;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request, CreateOrganization $createOrganization): RedirectResponse
    {
        $this->normalizeEmail($request);
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'organization_name' => ['required', 'string', 'max:120'],
            'password' => ['bail', 'required', 'string', 'min:12', 'confirmed', function (string $attribute, string $value, Closure $fail): void {
                if (strlen($value) > 72) {
                    $fail('Kata sandi tidak boleh melebihi 72 byte.');
                }
            }],
        ]);

        $user = DB::transaction(function () use ($createOrganization, $data, $request): User {
            try {
                $user = User::create([
                    'name' => $data['name'],
                    'email' => $data['email'],
                    'password' => $data['password'],
                ]);
            } catch (UniqueConstraintViolationException) {
                throw ValidationException::withMessages(['email' => __('validation.unique', ['attribute' => 'email'])]);
            }

            $name = $data['organization_name'];
            $slug = Str::slug($name) ?: 'organisasi';
            $createOrganization->handle($user, $name, $slug.'-'.Str::uuid(), $request->ip());

            return $user;
        });

        event(new Registered($user));
        Auth::login($user);
        $request->session()->regenerate();

        return to_route('dashboard');
    }

    public function login(Request $request): RedirectResponse
    {
        $this->normalizeEmail($request);
        $credentials = $request->validate([
            'email' => ['required', 'email', 'max:255'],
            'password' => ['required', 'string', 'max:255'],
        ]);

        if (! Auth::attempt($credentials)) {
            throw ValidationException::withMessages(['email' => __('auth.failed')]);
        }

        $request->session()->regenerate();

        return redirect()->intended(route('dashboard'));
    }

    public function logout(Request $request): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return to_route('login');
    }

    private function normalizeEmail(Request $request): void
    {
        $email = $request->input('email');

        if (is_string($email)) {
            $request->merge(['email' => Str::lower($email)]);
        }
    }
}
