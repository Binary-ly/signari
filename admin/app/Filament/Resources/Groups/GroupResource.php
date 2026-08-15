<?php

namespace App\Filament\Resources\Groups;

use App\Filament\Resources\Groups\Pages\ListGroups;
use App\Filament\Resources\Groups\Tables\GroupsTable;
use App\Models\Group;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Groups, their membership, and which applications can see them.
 *
 * Read-only. This configuration is written with the signari CLI, and the console
 * has no privilege on schema core (ADR-004) -- so showing it here is visibility,
 * not a second write path that could disagree with the engine.
 */
class GroupResource extends Resource
{
    protected static ?string $model = Group::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedUserGroup;

    protected static string|\UnitEnum|null $navigationGroup = 'Configuration';

    protected static ?string $navigationLabel = 'Groups';

    protected static ?string $modelLabel = 'group';

    protected static ?string $pluralModelLabel = 'Groups';


    public static function table(Table $table): Table
    {
        return GroupsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListGroups::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
