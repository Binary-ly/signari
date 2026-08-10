<?php

namespace App\Filament\Resources\EngineClients\Tables;

use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class EngineClientsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('client_id')
                    ->searchable()->sortable()->copyable()
                    ->description(fn ($record) => $record->display_name),

                TextColumn::make('client_type')
                    ->badge()
                    ->color(fn (string $s): string => $s === 'confidential' ? 'success' : 'info'),

                IconColumn::make('enabled')
                    ->boolean()
                    // Disabled is read from the database on every request, never
                    // cached -- a disabled client stops working on the very next
                    // call, which is the CVE class this design defends against.
                    ->tooltip(fn ($r): string => $r->enabled
                        ? 'Enabled'
                        : 'Disabled -- rejected on the next request, not the next cache refresh'),

                IconColumn::make('require_pkce')
                    ->label('PKCE')
                    ->boolean()
                    ->color(fn ($state, $record) => $record->isUnauthenticated() ? 'danger' : 'success')
                    ->tooltip(fn ($record): ?string => $record->isUnauthenticated()
                        ? 'Public client with PKCE off: anyone holding the client_id can redeem a code'
                        : null),

                TextColumn::make('redirect_uris')
                    ->label('Redirect URIs')
                    ->badge()
                    ->limitList(1)
                    ->expandableLimitedList()
                    // Matching is byte-for-byte, so the exact string matters and
                    // must be readable in full rather than truncated.
                    ->copyable(),

                IconColumn::make('backchannel_logout_uri')
                    ->label('Logout')
                    ->boolean()
                    ->getStateUsing(fn ($record): bool => $record->canReceiveLogout())
                    ->tooltip(fn ($record): ?string => $record->canReceiveLogout()
                        ? null
                        : 'No back-channel logout endpoint: this client cannot be told its user signed out'),

                TextColumn::make('id_token_signed_alg')->label('Alg')->badge()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('access_token_ttl_s')->label('AT TTL')
                    ->formatStateUsing(fn (int $s): string => $s.'s')
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('client_type')->options([
                    'confidential' => 'Confidential',
                    'public'       => 'Public',
                ]),
                Filter::make('disabled')
                    ->label('Disabled only')
                    ->query(fn (Builder $q): Builder => $q->where('enabled', false)),
                Filter::make('no_pkce')
                    ->label('Public clients without PKCE')
                    ->query(fn (Builder $q): Builder => $q
                        ->where('client_type', 'public')->where('require_pkce', false)),
                Filter::make('no_logout')
                    ->label('No back-channel logout endpoint')
                    ->query(fn (Builder $q): Builder => $q->whereNull('backchannel_logout_uri')),
            ])
            ->recordActions([])
            ->toolbarActions([])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading('No clients in scope')
            ->emptyStateDescription(
                'Rows are scoped to your organisation by row-level security. '.
                'An empty table means no organisation context, not an empty registry.'
            );
    }
}
