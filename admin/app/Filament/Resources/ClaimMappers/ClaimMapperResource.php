<?php

namespace App\Filament\Resources\ClaimMappers;

use App\Filament\Resources\ClaimMappers\Pages\ListClaimMappers;
use App\Filament\Resources\ReadOnlyResource;
use App\Models\ClaimMapper;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class ClaimMapperResource extends ReadOnlyResource
{
    protected static ?string $model = ClaimMapper::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedArrowsRightLeft;

    public static function getNavigationLabel(): string
    {
        return __('Claim mappers');
    }

    public static function getModelLabel(): string
    {
        return __('claim mapper');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Claim mappers');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('claim_name')->label(__('Claim'))->searchable()->sortable(),
                TextColumn::make('source')->label(__('From'))->badge(),
                TextColumn::make('attribute')->label(__('Attribute'))->placeholder('—'),
                TextColumn::make('destination')->label(__('Goes into')),
                TextColumn::make('required_scope')->label(__('Needs scope'))->placeholder('—'),
                TextColumn::make('client_id')->label(__('Client'))->placeholder(__('every client')),
            ])
            ->defaultSort('claim_name')
            ->emptyStateHeading(__('No claim mappers'))
            ->emptyStateDescription(__('Tokens carry the standard claims and nothing added.'));
    }

    public static function getPages(): array
    {
        return ['index' => ListClaimMappers::route('/')];
    }
}
