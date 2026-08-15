<?php

namespace App\Filament\Resources\ScimTargets;

use App\Filament\Resources\ScimTargets\Pages\ListScimTargets;
use App\Filament\Resources\ScimTargets\Tables\ScimTargetsTable;
use App\Models\ScimTarget;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * SCIM provisioning targets and whether they are actually writing.
 *
 * Read-only. This configuration is written with the signari CLI, and the console
 * has no privilege on schema core (ADR-004) -- so showing it here is visibility,
 * not a second write path that could disagree with the engine.
 */
class ScimTargetResource extends Resource
{
    protected static ?string $model = ScimTarget::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedArrowPath;

    protected static string|\UnitEnum|null $navigationGroup = 'Configuration';

    protected static ?string $navigationLabel = 'Provisioning';

    protected static ?string $modelLabel = 'SCIM target';

    protected static ?string $pluralModelLabel = 'Provisioning';

    /**
     * The count of MISCONFIGURED rows, not of all rows. A badge showing the total
     * is decoration; one showing what needs attention is a number to act on.
     */
    public static function getNavigationBadge(): ?string
    {
        $bad = ScimTarget::query()->where('config_state', '!=', 'ok')->count();

        return $bad > 0 ? (string) $bad : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'warning';
    }


    public static function table(Table $table): Table
    {
        return ScimTargetsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListScimTargets::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
