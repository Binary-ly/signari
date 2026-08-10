<?php

namespace App\Filament\Resources\EngineUsers;

use App\Filament\Resources\EngineUsers\Pages\ListEngineUsers;
use App\Filament\Resources\EngineUsers\Tables\EngineUsersTable;
use App\Models\EngineUser;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * Users, read-only.
 *
 * There is no create, edit or delete page, and that is architectural rather than
 * unfinished: the admin has no write access to schema `core` (ADR-004), so any
 * write form Filament rendered would be a button that cannot work. User changes
 * go through the engine's Admin API.
 *
 * Filament asks the model for its authorisation defaults, so these also stop the
 * framework generating routes and bulk actions for operations the database will
 * refuse.
 */
class EngineUserResource extends Resource
{
    protected static ?string $model = EngineUser::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedUsers;

    protected static ?string $modelLabel = 'user';

    protected static ?string $navigationLabel = 'Users';

    protected static ?int $navigationSort = 1;

    public static function table(Table $table): Table
    {
        return EngineUsersTable::configure($table);
    }

    public static function getPages(): array
    {
        return [
            'index' => ListEngineUsers::route('/'),
        ];
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit($record): bool
    {
        return false;
    }

    public static function canDelete($record): bool
    {
        return false;
    }

    public static function canDeleteAny(): bool
    {
        return false;
    }
}
