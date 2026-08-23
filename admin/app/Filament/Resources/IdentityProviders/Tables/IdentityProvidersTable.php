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
                    ->label(__('State'))
                    ->badge()
                    ->color(fn (string $state): string => $state === 'ok' ? 'success'
                        : ($state === 'disabled' ? 'gray' : 'danger'))
                    ->sortable(),

                TextColumn::make('display_name')
                    ->label(__('Provider'))
                    ->description(fn ($record) => $record->slug)
                    ->searchable(['display_name', 'slug'])
                    ->sortable(),

                TextColumn::make('kind')->label(__('Kind'))->badge()->sortable(),

                IconColumn::make('allow_signup')
                    ->label(__('Sign-up'))
                    ->boolean()
                    ->tooltip(__('Whether a person with no account here can create one through this provider')),

                IconColumn::make('allow_linking')
                    ->label(__('Linking'))
                    ->boolean()
                    ->tooltip(__('Whether an existing account can attach this provider. Linking is by (provider, subject) only — there is no email-matching path at any setting')),

                IconColumn::make('trust_email_verification')
                    ->label(__('Trusts email'))
                    ->boolean()
                    ->tooltip(__('Only turn this on for a provider you know verifies addresses. Sign-up refuses without it')),

                TextColumn::make('issuer')
                    ->label(__('Issuer'))
                    ->limit(40)
                    ->placeholder('—')
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('config_state')
            ->emptyStateHeading(__('No external sign-in providers'))
            ->emptyStateDescription(__('Add one with `signari idp add`.'));
    }
}
