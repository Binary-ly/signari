<?php

namespace App\Filament\Resources\EngineUsers\Tables;

use App\Services\EngineAdminApi;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use RuntimeException;

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
            ->headerActions([
                self::createUserAction(),
            ])
            ->recordActions([
                self::toggleActiveAction(),
                self::setPasswordAction(),
            ])
            ->toolbarActions([])
            ->defaultSort('created_at', 'desc')
            ->emptyStateHeading('No users in scope')
            ->emptyStateDescription(
                'Rows are scoped to your organisation by PostgreSQL row-level security. '.
                'An empty table means no organisation context, not an empty database.'
            );
    }

    /**
     * Create a user.
     *
     * The password field is deliberately OPTIONAL and empty by default. Inviting
     * somebody without a password means they set their own through recovery, and
     * nobody has to invent a credential on their behalf and then send it to them
     * over a channel neither of them chose.
     */
    private static function createUserAction(): Action
    {
        return Action::make('createUser')
            ->label('New user')
            ->icon('heroicon-m-user-plus')
            ->schema([
                TextInput::make('email')->email()->label('Email')
                    ->helperText('Email or username is required.'),
                TextInput::make('username')->label('Username'),
                TextInput::make('password')->password()->revealable()->minLength(8)
                    ->label('Password (optional)')
                    ->helperText('Leave blank to invite them: they set their own via recovery.'),
            ])
            ->action(function (array $data): void {
                // The organisation comes from the OPERATOR's own record, never
                // from the form. A tenant selector the caller can set is not a
                // tenant boundary -- the same rule ScopeToOrganisation enforces.
                $orgId = auth()->user()?->org_id;
                if (blank($orgId)) {
                    Notification::make()->title('You are not assigned to an organisation')
                        ->body('An operator with no organisation cannot create users in one.')
                        ->danger()->send();

                    return;
                }
                try {
                    EngineAdminApi::fromConfig()->createUser(
                        $orgId, $data['email'] ?? null, $data['username'] ?? null,
                        filled($data['password'] ?? null) ? $data['password'] : null
                    );
                } catch (RuntimeException $e) {
                    Notification::make()->title('User not created')->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title('User created')->success()->send();
            });
    }

    /**
     * Deactivating ends every session. The count is reported because "deactivated"
     * without it leaves an operator wondering whether the person is still signed
     * in somewhere -- which, in most identity systems, they are.
     */
    private static function toggleActiveAction(): Action
    {
        return Action::make('toggleActive')
            ->label(fn ($record): string => $record->status === 'active' ? 'Deactivate' : 'Reactivate')
            ->icon(fn ($record): string => $record->status === 'active'
                ? 'heroicon-m-no-symbol' : 'heroicon-m-check-circle')
            ->color(fn ($record): string => $record->status === 'active' ? 'danger' : 'success')
            ->requiresConfirmation()
            ->modalDescription(fn ($record): string => $record->status === 'active'
                ? 'They will be signed out of every application immediately, not just prevented from signing in again.'
                : 'They will be able to sign in again. Existing sessions were already ended and do not come back.')
            ->action(function ($record): void {
                try {
                    $r = EngineAdminApi::fromConfig()
                        ->setUserActive($record->id, $record->status !== 'active');
                } catch (RuntimeException $e) {
                    Notification::make()->title('Nothing was changed')->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                $ended = (int) ($r['sessions_ended'] ?? 0);
                Notification::make()
                    ->title($record->status === 'active' ? 'User deactivated' : 'User reactivated')
                    ->body($ended > 0 ? "{$ended} session(s) ended." : 'No sessions were open.')
                    ->success()->send();
            });
    }

    private static function setPasswordAction(): Action
    {
        return Action::make('setPassword')
            ->label('Set password')
            ->icon('heroicon-m-key')
            ->requiresConfirmation()
            ->modalDescription('Every existing session is ended: they all predate this credential.')
            ->schema([
                TextInput::make('password')->password()->revealable()->required()->minLength(8),
            ])
            ->action(function ($record, array $data): void {
                try {
                    $r = EngineAdminApi::fromConfig()->setUserPassword($record->id, $data['password']);
                } catch (RuntimeException $e) {
                    Notification::make()->title('Password not changed')->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title('Password set')
                    ->body(((int) ($r['sessions_ended'] ?? 0)).' session(s) ended.')
                    ->success()->send();
            });
    }
}
