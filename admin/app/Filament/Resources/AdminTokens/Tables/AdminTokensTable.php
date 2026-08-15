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
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'active'        => 'success',
                        'expiring soon' => 'warning',
                        'never used'    => 'warning',
                        default         => 'gray',
                    })
                    ->sortable(),

                TextColumn::make('name')
                    ->searchable()
                    ->sortable(),

                TextColumn::make('scopes')
                    ->badge()
                    ->separator(',')
                    ->tooltip('What this credential may do. A token holding fewer scopes is '
                        .'less to lose if it leaks'),

                // "Is anyone still using this" is the question you ask before
                // revoking, and it is the only reason this column exists.
                TextColumn::make('last_used_at')
                    ->label('Last used')
                    ->since()
                    ->placeholder('never')
                    ->sortable(),

                TextColumn::make('expires_at')
                    ->label('Expires')
                    ->dateTime()
                    ->placeholder('never')
                    ->color(fn ($record): string => $record->state === 'expiring soon' ? 'warning' : 'gray')
                    ->sortable(),

                TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('state')->options([
                    'active'        => 'active',
                    'expiring soon' => 'expiring soon',
                    'never used'    => 'never used',
                    'expired'       => 'expired',
                    'revoked'       => 'revoked',
                ]),
            ])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading('No admin tokens for this organisation')
            ->emptyStateDescription('Mint one with `signari admin-token create -org <uuid>`. '
                .'Deployment-wide tokens are not listed here.');
    }
}
