<?php

namespace App\Filament\Resources\EngineUsers\Tables;

use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class EngineUsersTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('email')
                    ->searchable()
                    ->sortable()
                    ->description(fn ($record) => $record->username),

                TextColumn::make('status')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'active'      => 'success',
                        'deactivated' => 'danger',
                        'locked'      => 'warning',
                        default       => 'gray',
                    })
                    ->sortable(),

                TextColumn::make('passkey_count')
                    ->label('Passkeys')
                    ->badge()
                    // Two is the threshold for passwordless, not one: with a
                    // single passkey, losing the device locks the account out.
                    ->color(fn (int $state): string => $state >= 2 ? 'success' : ($state === 1 ? 'warning' : 'gray'))
                    ->tooltip(fn (int $state): string => $state >= 2
                        ? 'Can go passwordless'
                        : 'Needs 2+ passkeys before passwords can be removed')
                    ->sortable(),

                IconColumn::make('totp_enabled')->label('TOTP')->boolean(),

                // The migration signal. During an import from another provider the
                // number that matters is how many users have NOT yet signed in --
                // each of those is still carrying a foreign hash.
                IconColumn::make('password_is_current')
                    ->label('Hash current')
                    ->boolean()
                    ->tooltip(fn ($record): ?string => $record->needsRehash()
                        ? 'Imported hash, not yet rehashed. Rehashes silently on next sign-in.'
                        : null),

                TextColumn::make('migration_state')
                    ->badge()
                    ->color(fn (string $state): string => $state === 'pending' ? 'warning' : 'gray')
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('created_at')->dateTime()->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('status')->options([
                    'active'      => 'Active',
                    'deactivated' => 'Deactivated',
                    'locked'      => 'Locked',
                ]),

                Filter::make('needs_rehash')
                    ->label('Imported hash not yet upgraded')
                    ->query(fn (Builder $q): Builder => $q->where('has_password', true)
                        ->where('password_is_current', false)),

                Filter::make('passwordless_ready')
                    ->label('Ready for passwordless (2+ passkeys)')
                    ->query(fn (Builder $q): Builder => $q->where('passkey_count', '>=', 2)),
            ])
            // No row actions and no bulk actions: every one of them would be a
            // write, and the admin has none. See EngineUserResource.
            ->recordActions([])
            ->toolbarActions([])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading('No users in scope')
            ->emptyStateDescription(
                'Rows are scoped to your organisation by PostgreSQL row-level security. '.
                'An empty table means no organisation context, not an empty database.'
            );
    }
}
