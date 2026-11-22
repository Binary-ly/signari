<?php

namespace App\Filament\Resources\Scopes;

use App\Filament\Resources\ReadOnlyResource;
use App\Filament\Resources\Scopes\Pages\ListScopes;
use App\Models\OrgScope;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class ScopeResource extends ReadOnlyResource
{
    protected static ?string $model = OrgScope::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedKey;

    public static function getNavigationLabel(): string
    {
        return __('Scopes');
    }

    public static function getModelLabel(): string
    {
        return __('scope');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Scopes');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('name')->label(__('Scope'))->searchable()->sortable(),
                TextColumn::make('display_name')->label(__('Shown as'))->placeholder('—'),
                TextColumn::make('description')->label(__('Description'))->limit(60)->placeholder('—'),
                IconColumn::make('advertise')->label(__('Advertised'))->boolean(),
            ])
            ->defaultSort('name')
            ->emptyStateHeading(__('No scopes of its own'))
            ->emptyStateDescription(__('Declare them in a configuration file, or with `signari scope`.'));
    }

    public static function getPages(): array
    {
        return ['index' => ListScopes::route('/')];
    }
}
