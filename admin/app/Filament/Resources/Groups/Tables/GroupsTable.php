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
                    ->label('Group')
                    ->description(fn ($record) => $record->name)
                    ->searchable(['name', 'display_name'])
                    ->sortable(),

                TextColumn::make('member_count')
                    ->label('Members')
                    ->numeric()
                    ->sortable(),

                // Releases name groups by NAME, so this is the number to check
                // before renaming one: a rename silently drops the group from
                // every allow-list that mentioned it, and nothing errors.
                TextColumn::make('released_to_clients')
                    ->label('OIDC clients')
                    ->numeric()
                    ->tooltip('Applications allowed to see this membership. Releases match on '
                        .'the group NAME, so renaming the group removes it from these lists'),

                TextColumn::make('released_to_saml')
                    ->label('SAML providers')
                    ->numeric()
                    ->tooltip('Same, for SAML service providers'),

                TextColumn::make('description')
                    ->limit(50)
                    ->placeholder('—')
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('member_count', 'desc')
            ->emptyStateHeading('No groups')
            ->emptyStateDescription('Create one with `signari group create`.');
    }
}
