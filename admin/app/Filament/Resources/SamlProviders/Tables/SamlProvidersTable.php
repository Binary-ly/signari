<?php

namespace App\Filament\Resources\SamlProviders\Tables;

use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class SamlProvidersTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                // State first, because the reason to open this screen is almost
                // always "is anything broken", not "what is registered".
                TextColumn::make('config_state')
                    ->label('State')
                    ->badge()
                    ->color(fn (string $state): string => $state === 'ok' ? 'success'
                        : ($state === 'disabled' ? 'gray' : 'danger'))
                    ->sortable(),

                TextColumn::make('display_name')
                    ->label('Service provider')
                    ->description(fn ($record) => $record->entity_id)
                    ->searchable(['display_name', 'entity_id'])
                    ->sortable(),

                TextColumn::make('name_id_format')
                    ->label('NameID')
                    ->badge()
                    ->color(fn (string $state): string => $state === 'persistent' ? 'success' : 'warning')
                    // persistent is pairwise: the provider sees an identifier no
                    // other provider can correlate, and it survives an email change.
                    ->tooltip(fn (string $state): string => $state === 'persistent'
                        ? 'Pairwise: this provider cannot correlate its users with any other'
                        : 'Not pairwise: the identifier is shared, and changing it creates a new account'),

                IconColumn::make('want_authn_requests_signed')
                    ->label('Signed requests')
                    ->boolean(),

                IconColumn::make('assertions_encrypted')
                    ->label('Encrypted')
                    ->boolean()
                    ->tooltip('Assertions are encrypted to this provider’s certificate, on top of TLS'),

                TextColumn::make('logout_url')
                    ->label('Single logout')
                    ->placeholder('not configured')
                    ->limit(40)
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('config_state')
                    ->label('State')
                    ->options([
                        'ok' => 'ok',
                        'signing required, no certificate' => 'signing required, no certificate',
                        'logout configured, no certificate' => 'logout configured, no certificate',
                        'disabled' => 'disabled',
                    ]),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading('No SAML service providers')
            ->emptyStateDescription('Register one with `signari saml add-sp`.');
    }
}
