@extends('layouts.portal')

@section('portal-content')
    @if (session('status'))
        <p role="status" class="rounded-xl border border-signal/30 bg-signal-bg px-4 py-3 text-sm text-signal">{{ session('status') }}</p>
    @endif
    @if ($errors->any())
        <ul role="alert" class="list-disc rounded-xl border border-red-500/35 bg-red-500/10 py-3 pr-4 pl-8 text-sm">
            @foreach ($errors->all() as $error)
                <li>{{ $error }}</li>
            @endforeach
        </ul>
    @endif
    @yield('domain-content')
@endsection
