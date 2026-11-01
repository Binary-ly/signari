<?php

namespace App\Filament\Resources\AuthorizationModels;

use App\Filament\Resources\AuthorizationModels\Pages\ListAuthorizationModels;
use App\Filament\Resources\AuthorizationModels\Tables\AuthorizationModelsTable;
use App\Models\AuthorizationModel;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * The authorization model in force.
 *
 * Read-only: it is written with the signari CLI, or applied as configuration,
 * either of which runs its tests first.
 */
class AuthorizationModelResource extends Resource
{
    protected static ?string $model = AuthorizationModel::class;

    /** What an operator signed in through Signari needs to see this screen (6.06). */
    public static function canViewAny(): bool
    {
        return SignariSignIn::may('config:read');
    }

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldCheck;

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('Authorization model');
    }

    public static function getModelLabel(): string
    {
        return __('authorization model');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Authorization model');
    }

    public static function table(Table $table): Table
    {
        return AuthorizationModelsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListAuthorizationModels::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
