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
                    ->label(__('State'))
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => __($state))
                    ->color(fn (string $state): string => $state === 'ok' ? 'success'
                        : ($state === 'disabled' ? 'gray' : 'danger'))
                    ->sortable(),

                TextColumn::make('display_name')
                    ->label(__('Service provider'))
                    ->description(fn ($record) => $record->entity_id)
                    ->searchable(['display_name', 'entity_id'])
                    ->sortable(),

                TextColumn::make('name_id_format')
                    ->label(__('NameID'))
                    ->badge()
                    ->color(fn (string $state): string => $state === 'persistent' ? 'success' : 'warning')
                    // persistent is pairwise: the provider sees an identifier no
                    // other provider can correlate, and it survives an email change.
                    ->tooltip(fn (string $state): string => $state === 'persistent'
                        ? __('Pairwise: this provider cannot correlate its users with any other')
                        : __('Not pairwise: the identifier is shared, and changing it creates a new account')),

                IconColumn::make('want_authn_requests_signed')
                    ->label(__('Signed requests'))
                    ->boolean(),

                IconColumn::make('assertions_encrypted')
                    ->label(__('Encrypted'))
                    ->boolean()
                    ->tooltip(__('Assertions are encrypted to this provider’s certificate, on top of TLS')),

                TextColumn::make('logout_url')
                    ->label(__('Single logout'))
                    ->placeholder(__('not configured'))
                    ->limit(40)
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->label(__('Created'))
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                // The KEYS stay English because they are the stored values the
                // filter matches on; only what an operator reads is translated.
                SelectFilter::make('config_state')
                    ->label(__('State'))
                    ->options([
                        'ok' => __('ok'),
                        'signing required, no certificate' => __('signing required, no certificate'),
                        'logout configured, no certificate' => __('logout configured, no certificate'),
                        'disabled' => __('disabled'),
                    ]),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading(__('No SAML service providers'))
            ->emptyStateDescription(__('Register one with `signari saml add-sp`.'));
    }
}
