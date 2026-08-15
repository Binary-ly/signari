<?php

namespace App\Filament\Resources\IdentityProviders;

use App\Filament\Resources\IdentityProviders\Pages\ListIdentityProviders;
use App\Filament\Resources\IdentityProviders\Tables\IdentityProvidersTable;
use App\Models\IdentityProvider;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * External sign-in providers users can authenticate through.
 *
 * Read-only. This configuration is written with the signari CLI, and the console
 * has no privilege on schema core (ADR-004) -- so showing it here is visibility,
 * not a second write path that could disagree with the engine.
 */
class IdentityProviderResource extends Resource
{
    protected static ?string $model = IdentityProvider::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedGlobeAlt;

    protected static string|\UnitEnum|null $navigationGroup = 'Configuration';

    protected static ?string $navigationLabel = 'Sign-in providers';

    protected static ?string $modelLabel = 'external sign-in provider';

    protected static ?string $pluralModelLabel = 'Sign-in providers';

    /**
     * The count of MISCONFIGURED rows, not of all rows. A badge showing the total
     * is decoration; one showing what needs attention is a number to act on.
     */
    public static function getNavigationBadge(): ?string
    {
        $bad = IdentityProvider::query()->where('config_state', '!=', 'ok')->count();

        return $bad > 0 ? (string) $bad : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'warning';
    }


    public static function table(Table $table): Table
    {
        return IdentityProvidersTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListIdentityProviders::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
