<?php

namespace App\Filament\Resources\LogoutDeliveries\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class LogoutDeliveriesTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('status')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'delivered' => 'success',
                        'pending'   => 'warning',
                        default     => 'danger',
                    })
                    ->sortable(),

                TextColumn::make('client_name')
                    ->label('Relying party')
                    ->description(fn ($record) => $record->client_id)
                    ->searchable(['client_id'])
                    ->sortable(),

                // The number that makes the problem concrete: how long this
                // application has been wrong about whether the user is signed in.
                TextColumn::make('age')
                    ->label('Wrong for')
                    ->formatStateUsing(fn ($state): string => self::humanise($state))
                    ->color(fn ($record): string => $record->status === 'delivered' ? 'gray' : 'danger'),

                TextColumn::make('attempts')
                    ->label('Tries')
                    ->alignRight()
                    ->color(fn ($record): string => $record->attempts >= 8 ? 'danger' : 'gray'),

                TextColumn::make('last_error')
                    ->label('Last error')
                    ->limit(60)
                    ->tooltip(fn ($record) => $record->last_error)
                    ->placeholder('—')
                    ->toggleable(),

                TextColumn::make('backchannel_logout_uri')
                    ->label('Endpoint')
                    ->limit(40)
                    // A relying party with no endpoint registered cannot be told
                    // anything. That is a configuration gap, not an outage, and
                    // conflating the two sends operators chasing the wrong thing.
                    ->placeholder('not registered')
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('queued_at')->dateTime()->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
                TextColumn::make('delivered_at')->dateTime()->placeholder('—')->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('status')->options([
                    'parked'    => 'Parked (gave up)',
                    'pending'   => 'Pending',
                    'delivered' => 'Delivered',
                ]),
                Filter::make('unreachable')
                    ->label('No endpoint registered')
                    ->query(fn (Builder $q): Builder => $q->whereNull('backchannel_logout_uri')),
            ])
            // Parked first, then oldest. The default view answers "what is broken
            // right now", which is the only reason anyone opens this screen.
            ->defaultSort('queued_at', 'desc')
            ->recordActions([])
            ->toolbarActions([])
            ->emptyStateHeading('No logout notices yet')
            ->emptyStateDescription(
                'Every relying party that saw a session gets a back-channel logout notice '.
                'when that session ends. Their delivery state appears here.'
            );
    }

    /** PostgreSQL intervals arrive as strings; show something a person can read. */
    private static function humanise(mixed $state): string
    {
        if (blank($state)) {
            return '—';
        }

        return (string) $state;
    }
}
