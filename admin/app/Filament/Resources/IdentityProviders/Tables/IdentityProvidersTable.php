<?php

namespace App\Filament\Resources\IdentityProviders\Tables;

use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class IdentityProvidersTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('config_state')
                    ->label('State')
                    ->badge()
                    ->color(fn (string $state): string => $state === 'ok' ? 'success'
                        : ($state === 'disabled' ? 'gray' : 'danger'))
                    ->sortable(),

                TextColumn::make('display_name')
                    ->label('Provider')
                    ->description(fn ($record) => $record->slug)
                    ->searchable(['display_name', 'slug'])
                    ->sortable(),

                TextColumn::make('kind')->badge()->sortable(),

                IconColumn::make('allow_signup')
                    ->label('Sign-up')
                    ->boolean()
                    ->tooltip('Whether a person with no account here can create one through this provider'),

                IconColumn::make('allow_linking')
                    ->label('Linking')
                    ->boolean()
                    ->tooltip('Whether an existing account can attach this provider. Linking is by '
                        .'(provider, subject) only — there is no email-matching path at any setting'),

                IconColumn::make('trust_email_verification')
                    ->label('Trusts email')
                    ->boolean()
                    ->tooltip('Only turn this on for a provider you know verifies addresses. '
                        .'Sign-up refuses without it'),

                TextColumn::make('issuer')
                    ->limit(40)
                    ->placeholder('—')
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading('No external sign-in providers')
            ->emptyStateDescription('Add one with `signari idp add`.');
    }
}
