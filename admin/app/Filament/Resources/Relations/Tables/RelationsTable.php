<?php

namespace App\Filament\Resources\Relations\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class RelationsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('subject_id')
                    ->label(__('Subject'))
                    ->formatStateUsing(fn ($state, $record): string => $record->subject_type.':'.$state)
                    ->searchable(),

                TextColumn::make('relation')
                    ->label(__('Relation'))
                    ->badge()
                    ->searchable(),

                TextColumn::make('object_id')
                    ->label(__('Object'))
                    ->formatStateUsing(fn ($state, $record): string => $record->object_type.':'.$state)
                    ->searchable(),

                TextColumn::make('granted_at')
                    ->label(__('Granted'))
                    ->dateTime()
                    ->sortable(),

                TextColumn::make('expires_at')
                    ->label(__('Expires'))
                    ->dateTime()
                    ->placeholder(__('never'))
                    ->sortable(),
            ])
            ->defaultSort('id', 'desc')
            ->emptyStateHeading(__('No relations are held'))
            ->emptyStateDescription(__('Nobody holds anything directly. Somebody can still hold a relation through a parent or a team, which has no row of its own here.'));
    }
}
