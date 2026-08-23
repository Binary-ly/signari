<?php

namespace App\Filament\Resources\RadiusClients\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class RadiusClientsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('config_state')
                    ->label(__('State'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'ok'       => 'success',
                        'disabled' => 'gray',
                        default    => 'danger',
                    })
                    ->sortable(),

                TextColumn::make('name')
                    ->label(__('Device'))
                    ->searchable()
                    ->sortable(),

                // Part of the credential, not a comment. RADIUS has no handshake
                // and no certificate, so the source range and the shared secret
                // are the only two things that identify a device.
                TextColumn::make('network')
                    ->label(__('Source range'))
                    ->badge()
                    ->color('gray')
                    ->tooltip(__('Requests from outside this range get no reply at all — answering would confirm a RADIUS server is here')),

                TextColumn::make('created_at')
                    ->label(__('Created'))
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading(__('No RADIUS clients'))
            ->emptyStateDescription(__('Register one with `signari radius add-client`. The listener refuses to start without any: a server that trusts everybody is an authentication oracle for the whole network.'));
    }
}
