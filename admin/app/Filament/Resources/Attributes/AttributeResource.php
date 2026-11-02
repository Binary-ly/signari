<?php

namespace App\Filament\Resources\Attributes;

use App\Filament\Resources\Attributes\Pages\ListAttributes;
use App\Filament\Resources\ReadOnlyResource;
use App\Models\AttributeDefinition;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class AttributeResource extends ReadOnlyResource
{
    protected static ?string $model = AttributeDefinition::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedListBullet;

    public static function getNavigationLabel(): string
    {
        return __('Attributes');
    }

    public static function getModelLabel(): string
    {
        return __('attribute');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Attributes');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('name')->label(__('Attribute'))->searchable()->sortable(),
                TextColumn::make('display_name')->label(__('Shown as'))->placeholder('—'),
                TextColumn::make('value_type')->label(__('Type'))->badge(),
                IconColumn::make('personal')->label(__('Personal'))->boolean(),
                IconColumn::make('user_writable')->label(__('They may change it'))->boolean(),
                IconColumn::make('required')->label(__('Required'))->boolean(),
            ])
            ->defaultSort('name')
            ->emptyStateHeading(__('No attributes declared'))
            ->emptyStateDescription(__('People have the standard fields and nothing added.'));
    }

    public static function getPages(): array
    {
        return ['index' => ListAttributes::route('/')];
    }
}
