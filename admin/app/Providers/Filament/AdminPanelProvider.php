<?php

namespace App\Providers\Filament;

use App\Http\Middleware\ScopeToOrganisation;
use Filament\Http\Middleware\Authenticate;
use Filament\Http\Middleware\AuthenticateSession;
use Filament\Http\Middleware\DisableBladeIconComponents;
use Filament\Http\Middleware\DispatchServingFilamentEvent;
use Filament\Pages\Dashboard;
use Filament\Panel;
use Filament\PanelProvider;
use Filament\Support\Colors\Color;
use Filament\Widgets\AccountWidget;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;

class AdminPanelProvider extends PanelProvider
{
    public function panel(Panel $panel): Panel
    {
        return $panel
            ->default()
            ->id('admin')
            ->path('admin')
            ->login()
            ->brandName('Signari')
            /*
             * The engine's accent, so the console and the pages people sign in
             * through are recognisably the same product. An operator moves
             * between them constantly -- a client configured here is a consent
             * screen there -- and two palettes read as two systems.
             *
             * gray is Filament's own default (Zinc) named explicitly, because
             * it is load-bearing: it is what the engine's stylesheet derives
             * its borders and muted text from, so leaving it to a default that
             * could change is leaving the match to luck.
             */
            ->colors([
                'primary' => Color::hex('#3e63dd'),
                'gray' => Color::Zinc,
            ])
            ->discoverResources(in: app_path('Filament/Resources'), for: 'App\Filament\Resources')
            ->discoverPages(in: app_path('Filament/Pages'), for: 'App\Filament\Pages')
            ->pages([
                Dashboard::class,
            ])
            ->discoverWidgets(in: app_path('Filament/Widgets'), for: 'App\Filament\Widgets')
            /*
             * FilamentInfoWidget is deliberately not here. It is the framework's
             * own panel -- its wordmark, its version, links to its docs and its
             * GitHub -- and it was the largest thing on an operator's dashboard.
             *
             * Whose product this is matters more here than on most screens: the
             * console is where somebody decides whether a sign-in page asking
             * for their password is really ours.
             */
            ->widgets([
                AccountWidget::class,
            ])
            ->middleware([
                EncryptCookies::class,
                AddQueuedCookiesToResponse::class,
                StartSession::class,
                AuthenticateSession::class,
                ShareErrorsFromSession::class,
                PreventRequestForgery::class,
                SubstituteBindings::class,
                DisableBladeIconComponents::class,
                DispatchServingFilamentEvent::class,
            ])
            /*
             * authMiddleware, not middleware. ScopeToOrganisation resolves the
             * organisation from $request->user(), which is only populated once
             * Authenticate has run -- registered in the outer stack it would find
             * null on every request, set no context, and leave the console
             * permanently empty while looking correctly wired.
             *
             * Order matters within this list too: it must come after Authenticate.
             */
            ->authMiddleware([
                Authenticate::class,
                ScopeToOrganisation::class,
            ]);
    }
}
