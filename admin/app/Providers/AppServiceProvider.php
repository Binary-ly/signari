<?php

namespace App\Providers;

use App\Http\Middleware\EnsureSecondFactor;
use App\Http\Middleware\EnsureSignariSession;
use App\Services\SignariSignIn;
use Filament\Panel;
use Filament\Support\Assets\Css;
use Filament\Support\Facades\FilamentAsset;
use Filament\Support\Facades\FilamentView;
use Filament\View\PanelsRenderHook;
use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        /*
         * Signing in through Signari (6.06): every console request of an
         * operator who did is confirmed with the engine, Livewire's included
         * (persistent), and their second factor is the one Signari required,
         * not a console TOTP as well; a local account keeps the console's own.
         *
         * Here, not in boot: AdminPanelProvider builds the panel as it
         * registers, and a configuration added after that is never applied.
         * bootstrap/providers.php registers this provider first.
         */
        Panel::configureUsing(function (Panel $panel): void {
            $panel->authMiddleware([EnsureSignariSession::class], isPersistent: true)
                ->multiFactorAuthenticationRequiredMiddlewareName(EnsureSecondFactor::class);
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        /*
         * The console's stylesheet, published to public/css by
         * `php artisan filament:assets` -- which composer install already runs
         * through filament:upgrade, so there is no separate build or deploy
         * step. See resources/css/console.css for what it does and why.
         */
        FilamentAsset::register([
            Css::make('signari-console', __DIR__.'/../../resources/css/console.css'),
        ]);

        /*
         * The proxies config('app.trusted_proxies') names, and only those: their
         * X-Forwarded-* headers decide whether a request was secure, so HSTS is
         * sent behind a proxy that terminates TLS. Read from configuration rather
         * than in bootstrap/app.php, where env() is unreliable once the
         * configuration is cached.
         */
        $proxies = array_values(array_filter(array_map('trim',
            explode(',', (string) config('app.trusted_proxies')))));
        if ($proxies !== []) {
            TrustProxies::at($proxies);
        }

        /*
         * The Signari sign-in button above the password form, and a sign-out
         * that gives up the console's refresh token (6.06).
         */
        // The words are given here rather than written in the view, where
        // LocalisationTest's scan of app/ would not find them.
        FilamentView::registerRenderHook(PanelsRenderHook::AUTH_LOGIN_FORM_BEFORE,
            fn () => view('auth.signari-sign-in', [
                'signIn' => __('Sign in with Signari'),
                'breakGlass' => __('Or, when Signari itself is down, a break-glass account below.'),
            ]));
        Event::listen(Logout::class, fn () => app(SignariSignIn::class)->forget());
    }
}
