<?php

namespace App\Filament\Resources\Groups\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class GroupsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('display_name')
                    ->label(__('Group'))
                    ->description(fn ($record) => $record->name)
                    ->searchable(['name', 'display_name'])
                    ->sortable(),

                TextColumn::make('member_count')
                    ->label(__('Members'))
                    ->numeric()
                    ->sortable(),

                // Releases name groups by NAME, so this is the number to check
                // before renaming one: a rename silently drops the group from
                // every allow-list that mentioned it, and nothing errors.
                TextColumn::make('released_to_clients')
                    ->label(__('OIDC clients'))
                    ->numeric()
                    ->tooltip(__('Applications allowed to see this membership. Releases match on the group NAME, so renaming the group removes it from these lists')),

                TextColumn::make('released_to_saml')
                    ->label(__('SAML providers'))
                    ->numeric()
                    ->tooltip(__('Same, for SAML service providers')),

                TextColumn::make('description')
                    ->label(__('Description'))
                    ->limit(50)
                    ->placeholder('—')
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->label(__('Created'))
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('member_count', 'desc')
            ->emptyStateHeading(__('No groups'))
            ->emptyStateDescription(__('Create one with `signari group create`.'));
    }
}
