<?php

namespace App\Filament\Resources\Directories;

use App\Filament\Resources\Directories\Pages\ListDirectories;
use App\Filament\Resources\ReadOnlyResource;
use App\Models\DirectorySource;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

/**
 * Where people are synced from, and how the last run went. The credentials are not
 * in the view.
 */
class DirectoryResource extends ReadOnlyResource
{
    protected static ?string $model = DirectorySource::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedServerStack;

    public static function getNavigationLabel(): string
    {
        return __('Directories');
    }

    public static function getModelLabel(): string
    {
        return __('directory');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Directories');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('display_name')->label(__('Directory'))
                    ->description(fn ($record) => $record->slug)->searchable(['slug', 'display_name']),
                TextColumn::make('kind')->label(__('Kind'))->badge(),
                IconColumn::make('enabled')->label(__('Enabled'))->boolean(),
                IconColumn::make('dry_run')->label(__('Dry run'))->boolean(),
                TextColumn::make('last_sync_at')->label(__('Last sync'))->dateTime()->placeholder(__('never')),
                TextColumn::make('last_error')->label(__('Last error'))->limit(60)->placeholder('—'),
            ])
            ->defaultSort('slug')
            ->emptyStateHeading(__('No directories'))
            ->emptyStateDescription(__('People are made here, not synced from anywhere.'));
    }

    public static function getPages(): array
    {
        return ['index' => ListDirectories::route('/')];
    }
}
