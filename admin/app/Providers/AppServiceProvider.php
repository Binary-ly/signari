<?php

namespace App\Providers;

use Filament\Support\Assets\Css;
use Filament\Support\Facades\FilamentAsset;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
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
    }
}
