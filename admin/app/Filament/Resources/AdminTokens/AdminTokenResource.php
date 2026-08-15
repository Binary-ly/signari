<?php

namespace App\Filament\Resources\AdminTokens;

use App\Filament\Resources\AdminTokens\Pages\ListAdminTokens;
use App\Filament\Resources\AdminTokens\Tables\AdminTokensTable;
use App\Models\AdminToken;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Admin API credentials for this organisation, their scopes and their state.
 *
 * Read-only. This configuration is written with the signari CLI, and the console
 * has no privilege on schema core (ADR-004) -- so showing it here is visibility,
 * not a second write path that could disagree with the engine.
 */
class AdminTokenResource extends Resource
{
    protected static ?string $model = AdminToken::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedKey;

    protected static string|\UnitEnum|null $navigationGroup = 'Configuration';

    protected static ?string $navigationLabel = 'Admin tokens';

    protected static ?string $modelLabel = 'admin token';

    protected static ?string $pluralModelLabel = 'Admin tokens';

    /**
     * The count of MISCONFIGURED rows, not of all rows. A badge showing the total
     * is decoration; one showing what needs attention is a number to act on.
     */
    public static function getNavigationBadge(): ?string
    {
        $bad = AdminToken::query()->where('state', '!=', 'active')->count();

        return $bad > 0 ? (string) $bad : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'warning';
    }


    public static function table(Table $table): Table
    {
        return AdminTokensTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListAdminTokens::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
