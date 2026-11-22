<?php

namespace App\Filament\Resources\Relations;

use App\Filament\Resources\Relations\Pages\ListRelations;
use App\Filament\Resources\Relations\Tables\RelationsTable;
use App\Models\Relation;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Who holds what on what.
 *
 * Read-only. Relations are the application's data, written through the Admin
 * API as people and objects come and go.
 */
class RelationResource extends Resource
{
    protected static ?string $model = Relation::class;

    /** What an operator signed in through Signari needs to see this screen (6.06). */
    public static function canViewAny(): bool
    {
        return SignariSignIn::may('relations:read');
    }

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedLink;

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('Relations');
    }

    public static function getModelLabel(): string
    {
        return __('relation');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Relations');
    }

    public static function table(Table $table): Table
    {
        return RelationsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListRelations::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
