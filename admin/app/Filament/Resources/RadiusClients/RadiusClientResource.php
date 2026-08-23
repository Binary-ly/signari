<?php

namespace App\Filament\Resources\RadiusClients;

use App\Filament\Resources\RadiusClients\Pages\ListRadiusClients;
use App\Filament\Resources\RadiusClients\Tables\RadiusClientsTable;
use App\Models\RadiusClient;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Network devices permitted to send Access-Requests.
 *
 * Read-only. The console has no privilege on schema core (ADR-004); this is
 * written with the signari CLI.
 */
class RadiusClientResource extends Resource
{
    protected static ?string $model = RadiusClient::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedWifi;

    // Accessors rather than static properties: PHP cannot call __() in a
    // property initialiser. See AccessPolicyResource.

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('RADIUS clients');
    }

    public static function getModelLabel(): string
    {
        return __('RADIUS client');
    }

    public static function getPluralModelLabel(): string
    {
        return __('RADIUS clients');
    }

    /** Counts what needs attention, not what exists. */
    public static function getNavigationBadge(): ?string
    {
        $bad = RadiusClient::query()->where('config_state', '!=', 'ok')->count();

        return $bad > 0 ? (string) $bad : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'warning';
    }


    public static function table(Table $table): Table
    {
        return RadiusClientsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListRadiusClients::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
