<?php

namespace App\Filament\Resources\AdminTokens\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class AdminTokensTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('state')
                    ->label(__('State'))
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => __($state))
                    ->color(fn (string $state): string => match ($state) {
                        'active'        => 'success',
                        'expiring soon' => 'warning',
                        'never used'    => 'warning',
                        default         => 'gray',
                    })
                    ->sortable(),

                TextColumn::make('name')
                    ->label(__('Name'))
                    ->searchable()
                    ->sortable(),

                TextColumn::make('scopes')
                    ->label(__('Scopes'))
                    ->badge()
                    ->separator(',')
                    ->tooltip(__('What this credential may do. A token holding fewer scopes is less to lose if it leaks')),

                // "Is anyone still using this" is the question you ask before
                // revoking, and it is the only reason this column exists.
                TextColumn::make('last_used_at')
                    ->label(__('Last used'))
                    ->since()
                    ->placeholder(__('never'))
                    ->sortable(),

                TextColumn::make('expires_at')
                    ->label(__('Expires'))
                    ->dateTime()
                    ->placeholder(__('never'))
                    ->color(fn ($record): string => $record->state === 'expiring soon' ? 'warning' : 'gray')
                    ->sortable(),

                TextColumn::make('created_at')
                    ->label(__('Created'))
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                // The KEYS stay English because they are the stored values the
                // filter matches on; only what an operator reads is translated.
                SelectFilter::make('state')->label(__('State'))->options([
                    'active'        => __('active'),
                    'expiring soon' => __('expiring soon'),
                    'never used'    => __('never used'),
                    'expired'       => __('expired'),
                    'revoked'       => __('revoked'),
                ]),
            ])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading(__('No admin tokens for this organisation'))
            ->emptyStateDescription(__('Mint one with `signari admin-token create -org <uuid>`. Deployment-wide tokens are not listed here.'));
    }
}
