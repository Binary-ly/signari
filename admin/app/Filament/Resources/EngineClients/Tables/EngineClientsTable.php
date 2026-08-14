<?php

namespace App\Filament\Resources\EngineClients\Tables;

use App\Services\EngineAdminApi;
use Filament\Actions\Action;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
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
            ->headerActions([
                self::createClientAction(),
            ])
            ->recordActions([
                self::toggleEnabledAction(),
                self::rotateSecretAction(),
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

    /**
     * Register an application.
     *
     * The optional "existing secret" field is the migration path: an application
     * moving from another provider keeps the credential it already has, so the
     * move is a configuration change of one URL rather than a coordinated
     * release on their side.
     */
    private static function createClientAction(): Action
    {
        return Action::make('createClient')
            ->label('New client')
            ->icon('heroicon-m-plus')
            ->schema([
                TextInput::make('client_id')->required()
                    ->helperText('What the application sends as client_id. Settable verbatim, so an imported app keeps its own.'),
                TextInput::make('display_name')->label('Display name'),
                Toggle::make('public')->label('Public client (mobile or SPA)')
                    ->helperText('Public clients authenticate with PKCE and get no secret: a secret in a distributable binary is not a secret.'),
                // A textarea rather than a repeater: registering an application
                // usually means pasting the list its documentation gives you, and
                // one-per-line is the shape that arrives from a clipboard.
                Textarea::make('redirect_uris')
                    ->label('Redirect URIs (one per line)')
                    ->required()->rows(3)
                    ->helperText('Matched EXACTLY. No wildcards, no trailing-slash tolerance.'),
                TextInput::make('secret')->label('Existing secret (optional)')
                    ->password()->revealable()
                    ->helperText('Only when migrating an app that already has one. Leave blank to generate.'),
            ])
            ->action(function (array $data): void {
                $orgId = auth()->user()?->org_id;
                if (blank($orgId)) {
                    Notification::make()->title('You are not assigned to an organisation')
                        ->danger()->send();

                    return;
                }
                try {
                    $r = EngineAdminApi::fromConfig()->createClient(
                        $orgId, $data['client_id'], $data['display_name'] ?: $data['client_id'],
                        self::splitURIs($data['redirect_uris'] ?? ''),
                        (bool) ($data['public'] ?? false),
                        filled($data['secret'] ?? null) ? $data['secret'] : null,
                    );
                } catch (RuntimeException $e) {
                    Notification::make()->title('Client not created')->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                self::announceSecret('Client created', $r['client_secret'] ?? null);
            });
    }

    /** One URI per line, blanks and stray whitespace discarded. */
    private static function splitURIs(string $raw): array
    {
        return array_values(array_filter(array_map('trim', preg_split('/\r?\n/', $raw))));
    }

    private static function rotateSecretAction(): Action
    {
        return Action::make('rotateSecret')
            ->label('Rotate secret')
            ->icon('heroicon-m-arrow-path')
            ->color('warning')
            ->visible(fn ($record): bool => $record->client_type === 'confidential')
            ->requiresConfirmation()
            ->modalHeading(fn ($record): string => 'Rotate the secret for '.$record->client_id)
            // Stated plainly, because the usual expectation is an overlap window
            // and there is not one. Rotation is what you do when a secret has
            // leaked, and a window in which the leaked value still works is the
            // thing you were trying to end.
            ->modalDescription('The current secret stops working IMMEDIATELY. Any deployment still using it will fail to get tokens until it is updated.')
            ->action(function ($record): void {
                try {
                    $r = EngineAdminApi::fromConfig()->rotateClientSecret($record->client_id);
                } catch (RuntimeException $e) {
                    Notification::make()->title('Nothing was rotated')->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                self::announceSecret('Secret rotated', $r['client_secret'] ?? null);
            });
    }

    /**
     * Show a secret exactly once.
     *
     * Persistent, because a toast that fades takes the only copy with it: the
     * engine stores a hash, so this notification is the sole opportunity to read
     * the value. The wording says so rather than assuming the operator knows.
     */
    private static function announceSecret(string $title, ?string $secret): void
    {
        if (blank($secret)) {
            Notification::make()->title($title)->success()->send();

            return;
        }
        Notification::make()
            ->title($title)
            ->body("Copy this now — it is stored only as a hash and cannot be shown again:\n\n{$secret}")
            ->success()
            ->persistent()
            ->send();
    }
}
