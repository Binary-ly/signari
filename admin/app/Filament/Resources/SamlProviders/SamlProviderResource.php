<?php

namespace App\Filament\Resources\SamlProviders;

use App\Filament\Resources\SamlProviders\Pages\ListSamlProviders;
use App\Filament\Resources\SamlProviders\Tables\SamlProvidersTable;
use App\Models\SamlProvider;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Registered SAML service providers and whether each is fully configured.
 *
 * Read-only. This configuration is written with the signari CLI, and the console
 * has no privilege on schema core (ADR-004) -- so showing it here is visibility,
 * not a second write path that could disagree with the engine.
 */
class SamlProviderResource extends Resource
{
    protected static ?string $model = SamlProvider::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldCheck;

    // Accessors rather than static properties: PHP cannot call __() in a
    // property initialiser. See AccessPolicyResource.

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('SAML providers');
    }

    public static function getModelLabel(): string
    {
        return __('SAML service provider');
    }

    public static function getPluralModelLabel(): string
    {
        return __('SAML providers');
    }

    /**
     * The count of MISCONFIGURED rows, not of all rows. A badge showing the total
     * is decoration; one showing what needs attention is a number to act on.
     */
    public static function getNavigationBadge(): ?string
    {
        $bad = SamlProvider::query()->where('config_state', '!=', 'ok')->count();

        return $bad > 0 ? (string) $bad : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'warning';
    }


    public static function table(Table $table): Table
    {
        return SamlProvidersTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListSamlProviders::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
