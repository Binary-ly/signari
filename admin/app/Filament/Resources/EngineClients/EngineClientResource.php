<?php

namespace App\Filament\Resources\EngineClients;

use App\Filament\Resources\EngineClients\Pages\ListEngineClients;
use App\Filament\Resources\EngineClients\Tables\EngineClientsTable;
use App\Models\EngineClient;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

class EngineClientResource extends Resource
{
    protected static ?string $model = EngineClient::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedCubeTransparent;

    protected static ?string $modelLabel = 'client';

    protected static ?string $navigationLabel = 'Clients';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'client_id';

    public static function table(Table $table): Table
    {
        return EngineClientsTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListEngineClients::route('/')];
    }

    public static function canCreate(): bool { return false; }
    public static function canEdit($record): bool { return false; }
    public static function canDelete($record): bool { return false; }
    public static function canDeleteAny(): bool { return false; }
}
