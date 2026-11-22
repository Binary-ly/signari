<?php

namespace App\Filament\Resources\Groups\Tables;

use App\Models\EngineUser;
use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use RuntimeException;

class GroupsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('display_name')
                    ->label(__('Group'))
                    ->description(fn ($record) => $record->name)
                    ->searchable(['name', 'display_name'])
                    ->sortable(),

                TextColumn::make('member_count')
                    ->label(__('Members'))
                    ->numeric()
                    ->sortable(),

                // Releases name groups by NAME, so this is the number to check
                // before renaming one: a rename silently drops the group from
                // every allow-list that mentioned it, and nothing errors.
                TextColumn::make('released_to_clients')
                    ->label(__('OIDC clients'))
                    ->numeric()
                    ->tooltip(__('Applications allowed to see this membership. Releases match on the group NAME, so renaming the group removes it from these lists')),

                TextColumn::make('released_to_saml')
                    ->label(__('SAML providers'))
                    ->numeric()
                    ->tooltip(__('Same, for SAML service providers')),

                TextColumn::make('description')
                    ->label(__('Description'))
                    ->limit(50)
                    ->placeholder('—')
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->label(__('Created'))
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->recordActions([self::memberAction('addMember', true), self::memberAction('removeMember', false)])
            ->defaultSort('member_count', 'desc')
            ->emptyStateHeading(__('No groups'))
            ->emptyStateDescription(__('Create one with `signari group create`.'));
    }

    /**
     * Add or take away a member, found by address in this organisation's own people:
     * the view holds nobody else's, so nobody else can be named.
     */
    private static function memberAction(string $name, bool $add): Action
    {
        return Action::make($name)
            ->label($add ? __('Add a member') : __('Remove a member'))
            ->visible(fn (): bool => SignariSignIn::may('groups:write'))
            ->schema([TextInput::make('email')->label(__('Email'))->email()->required()])
            ->action(function (array $data, $record, $livewire) use ($add): void {
                $person = EngineUser::query()->where('email', $data['email'])->first();
                if ($person === null) {
                    Notification::make()->title(__('Nobody here has that address'))->danger()->send();

                    return;
                }
                try {
                    $api = EngineAdminApi::fromConfig()->asOf($livewire->renderedConfigVersion ?? null);
                    $add ? $api->addGroupMember($record->id, $person->id) : $api->removeGroupMember($record->id, $person->id);
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title($add ? __('Member added') : __('Member removed'))->success()->send();
            });
    }
}
