<?php

namespace App\Filament\Resources\EngineClients\Tables;

use App\Services\EngineAdminApi;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use RuntimeException;

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
                    ->color(fn (string $state): string => $state === 'confidential' ? 'success' : 'info'),

                IconColumn::make('enabled')
                    ->boolean()
                    // Disabled is read from the database on every request, never
                    // cached -- a disabled client stops working on the very next
                    // call, which is the CVE class this design defends against.
                    ->tooltip(fn ($record): string => $record->enabled
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
                    ->formatStateUsing(fn (int $state): string => $state.'s')
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
            ->recordActions([
                self::toggleEnabledAction(),
            ])
            ->toolbarActions([])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading('No clients in scope')
            ->emptyStateDescription(
                'Rows are scoped to your organisation by row-level security. '.
                'An empty table means no organisation context, not an empty registry.'
            );
    }

    /**
     * Enable or disable a client through the engine's Admin API.
     *
     * This does NOT write to the database. It cannot: signari_admin has no privilege
     * on schema core (ADR-004), and core_v1.clients is a read-only view. The
     * engine owns the write, and owning it is what guarantees config_version is
     * bumped in the same transaction -- an update issued from here would be
     * durable but invisible to every running node.
     *
     * Disabling is the operator's emergency stop for a leaked client secret, so
     * it is worth being precise about what it promises: the engine reads
     * `enabled` on the request path, so rejection begins with the next request,
     * not the next cache refresh.
     */
    private static function toggleEnabledAction(): Action
    {
        return Action::make('toggleEnabled')
            ->label(fn ($record): string => $record->enabled ? 'Disable' : 'Enable')
            ->icon(fn ($record): string => $record->enabled ? 'heroicon-m-no-symbol' : 'heroicon-m-check-circle')
            ->color(fn ($record): string => $record->enabled ? 'danger' : 'success')
            ->requiresConfirmation()
            ->modalHeading(fn ($record): string => ($record->enabled ? 'Disable ' : 'Enable ').$record->client_id)
            // Said plainly, because the blast radius of disabling a live client is
            // every sign-in through it, starting immediately.
            ->modalDescription(fn ($record): string => $record->enabled
                ? 'Every authorization and token request from this client starts failing on the next request. Sessions already issued are not revoked.'
                : 'This client can request authorization and tokens again from the next request.')
            ->action(function ($record): void {
                try {
                    $version = EngineAdminApi::fromConfig()
                        ->setClientEnabled($record->client_id, ! $record->enabled);
                } catch (RuntimeException $e) {
                    // The engine refused or is unreachable. Nothing changed, and
                    // saying so beats a green toast over a failed write.
                    Notification::make()
                        ->title('Nothing was changed')
                        ->body($e->getMessage())
                        ->danger()
                        ->persistent()
                        ->send();

                    return;
                }

                Notification::make()
                    ->title($record->enabled ? 'Client disabled' : 'Client enabled')
                    // The version is the operator's evidence the change reached
                    // the engine rather than merely the database.
                    ->body("Engine config version is now {$version}.")
                    ->success()
                    ->send();
            });
    }
}
