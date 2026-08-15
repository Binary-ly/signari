<?php

namespace App\Filament\Resources\ScimTargets\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class ScimTargetsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('config_state')
                    ->label('State')
                    ->badge()
                    ->color(fn (string $state): string => match (true) {
                        $state === 'ok'       => 'success',
                        $state === 'disabled' => 'gray',
                        default               => 'warning',
                    })
                    ->sortable(),

                TextColumn::make('display_name')
                    ->label('Target')
                    ->description(fn ($record) => $record->base_url)
                    ->searchable(['display_name', 'slug', 'base_url'])
                    ->sortable(),

                TextColumn::make('linked_users')
                    ->label('Users')
                    ->numeric()
                    ->sortable(),

                // The number that means something is wrong downstream: people who
                // should be gone from this application and are not.
                TextColumn::make('pending_deactivations')
                    ->label('Still active')
                    ->numeric()
                    ->color(fn ($state): string => $state > 0 ? 'danger' : 'gray')
                    ->tooltip('Users deactivated here who are still active at the target. '
                        .'`signari scim verify` reads each one back to confirm'),

                TextColumn::make('on_deactivate')
                    ->label('On deactivate')
                    ->badge(),

                TextColumn::make('last_synced_at')
                    ->label('Last sync')
                    ->since()
                    ->placeholder('never'),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading('No provisioning targets')
            ->emptyStateDescription('Add one with `signari scim add`.');
    }
}
