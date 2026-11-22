{{--
    Signing in through Signari (6.06), above the password form, which from
    here on admits only a break-glass account. Rendered only once Signari
    sign-in is configured; until then the page is the password form alone.
--}}
@if (\App\Services\SignariSignIn::configured())
    <div style="display: grid; gap: 0.75rem;">
        @if (session('signari_error'))
            <p role="alert">{{ session('signari_error') }}</p>
        @endif
        <x-filament::button tag="a" :href="route('signari.login')" size="lg">
            {{ $signIn }}
        </x-filament::button>
        <p>{{ $breakGlass }}</p>
    </div>
@endif
