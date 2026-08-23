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
                    ->label(__('Email'))
                    ->searchable()
                    ->sortable()
                    ->description(fn ($record) => $record->username),

                TextColumn::make('status')
                    ->label(__('Status'))
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => __($state))
                    ->color(fn (string $state): string => match ($state) {
                        'active'      => 'success',
                        'deactivated' => 'danger',
                        'locked'      => 'warning',
                        default       => 'gray',
                    })
                    ->sortable(),

                TextColumn::make('passkey_count')
                    ->label(__('Passkeys'))
                    ->badge()
                    // Two is the threshold for passwordless, not one: with a
                    // single passkey, losing the device locks the account out.
                    ->color(fn (int $state): string => $state >= 2 ? 'success' : ($state === 1 ? 'warning' : 'gray'))
                    ->tooltip(fn (int $state): string => $state >= 2
                        ? __('Can go passwordless')
                        : __('Needs 2+ passkeys before passwords can be removed'))
                    ->sortable(),

                IconColumn::make('totp_enabled')->label(__('TOTP'))->boolean(),

                // The migration signal. During an import from another provider the
                // number that matters is how many users have NOT yet signed in --
                // each of those is still carrying a foreign hash.
                IconColumn::make('password_is_current')
                    ->label(__('Hash current'))
                    ->boolean()
                    ->tooltip(fn ($record): ?string => $record->needsRehash()
                        ? __('Imported hash, not yet rehashed. Rehashes silently on next sign-in.')
                        : null),

                TextColumn::make('migration_state')
                    ->label(__('Migration'))
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => __($state))
                    ->color(fn (string $state): string => $state === 'pending' ? 'warning' : 'gray')
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('created_at')->label(__('Created'))->dateTime()->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                // The KEYS stay English because they are the stored values the
                // filter matches on; only what an operator reads is translated.
                SelectFilter::make('status')->label(__('Status'))->options([
                    'active'      => __('Active'),
                    'deactivated' => __('Deactivated'),
                    'locked'      => __('Locked'),
                ]),

                Filter::make('needs_rehash')
                    ->label(__('Imported hash not yet upgraded'))
                    ->query(fn (Builder $q): Builder => $q->where('has_password', true)
                        ->where('password_is_current', false)),

                Filter::make('passwordless_ready')
                    ->label(__('Ready for passwordless (2+ passkeys)'))
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
            ->emptyStateHeading(__('No users in scope'))
            ->emptyStateDescription(
                __('Rows are scoped to your organisation by PostgreSQL row-level security. An empty table means no organisation context, not an empty database.')
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
            ->label(__('New user'))
            ->icon('heroicon-m-user-plus')
            ->schema([
                TextInput::make('email')->email()->label(__('Email'))
                    ->helperText(__('Email or username is required.')),
                TextInput::make('username')->label(__('Username')),
                TextInput::make('password')->password()->revealable()->minLength(8)
                    ->label(__('Password (optional)'))
                    ->helperText(__('Leave blank to invite them: they set their own via recovery.')),
            ])
            ->action(function (array $data): void {
                // The organisation comes from the OPERATOR's own record, never
                // from the form. A tenant selector the caller can set is not a
                // tenant boundary -- the same rule ScopeToOrganisation enforces.
                $orgId = auth()->user()?->org_id;
                if (blank($orgId)) {
                    Notification::make()->title(__('You are not assigned to an organisation'))
                        ->body(__('An operator with no organisation cannot create users in one.'))
                        ->danger()->send();

                    return;
                }
                try {
                    EngineAdminApi::fromConfig()->createUser(
                        $orgId, $data['email'] ?? null, $data['username'] ?? null,
                        filled($data['password'] ?? null) ? $data['password'] : null
                    );
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('User not created'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title(__('User created'))->success()->send();
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
            ->label(fn ($record): string => $record->status === 'active' ? __('Deactivate') : __('Reactivate'))
            ->icon(fn ($record): string => $record->status === 'active'
                ? 'heroicon-m-no-symbol' : 'heroicon-m-check-circle')
            ->color(fn ($record): string => $record->status === 'active' ? 'danger' : 'success')
            ->requiresConfirmation()
            ->modalDescription(fn ($record): string => $record->status === 'active'
                ? __('They will be signed out of every application immediately, not just prevented from signing in again.')
                : __('They will be able to sign in again. Existing sessions were already ended and do not come back.'))
            ->action(function ($record): void {
                try {
                    $r = EngineAdminApi::fromConfig()
                        ->setUserActive($record->id, $record->status !== 'active');
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                $ended = (int) ($r['sessions_ended'] ?? 0);
                Notification::make()
                    ->title($record->status === 'active' ? __('User deactivated') : __('User reactivated'))
                    // trans_choice, not "session(s)": the same defect the
                    // front-channel logout page had, and wrong in English at one.
                    ->body($ended > 0 ? self::endedSessions($ended) : __('No sessions were open.'))
                    ->success()->send();
            });
    }

    private static function setPasswordAction(): Action
    {
        return Action::make('setPassword')
            ->label(__('Set password'))
            ->icon('heroicon-m-key')
            ->requiresConfirmation()
            ->modalDescription(__('Every existing session is ended: they all predate this credential.'))
            ->schema([
                TextInput::make('password')->label(__('Password'))
                    ->password()->revealable()->required()->minLength(8),
            ])
            ->action(function ($record, array $data): void {
                try {
                    $r = EngineAdminApi::fromConfig()->setUserPassword($record->id, $data['password']);
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Password not changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title(__('Password set'))
                    ->body(self::endedSessions((int) ($r['sessions_ended'] ?? 0)))
                    ->success()->send();
            });
    }

    /** How many sessions were ended, in a form that reads correctly at one. */
    private static function endedSessions(int $n): string
    {
        return trans_choice('{0}No sessions were open.|{1}:count session ended.|[2,*]:count sessions ended.',
            $n, ['count' => $n]);
    }
}
