<?php

namespace App\Filament\Resources\ScimSources;

use App\Filament\Resources\ReadOnlyResource;
use App\Filament\Resources\ScimSources\Pages\ListScimSources;
use App\Models\ScimSource;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

/** The systems that provision people into this organisation over SCIM. */
class ScimSourceResource extends ReadOnlyResource
{
    protected static ?string $model = ScimSource::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedArrowDownTray;

    public static function getNavigationLabel(): string
    {
        return __('Inbound SCIM');
    }

    public static function getModelLabel(): string
    {
        return __('SCIM source');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Inbound SCIM');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('display_name')->label(__('Source'))
                    ->description(fn ($record) => $record->slug)->searchable(['slug', 'display_name']),
                IconColumn::make('enabled')->label(__('Enabled'))->boolean(),
                TextColumn::make('on_delete')->label(__('When it deletes somebody'))->badge(),
                TextColumn::make('last_seen_at')->label(__('Last heard from'))->dateTime()->placeholder(__('never')),
            ])
            ->defaultSort('slug')
            ->emptyStateHeading(__('No SCIM sources'))
            ->emptyStateDescription(__('Nothing provisions people into this organisation.'));
    }

    public static function getPages(): array
    {
        return ['index' => ListScimSources::route('/')];
    }
}
