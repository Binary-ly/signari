<?php

namespace App\Filament\Resources\OrgMessages\Tables;

use App\Models\OrgMessage;
use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use Filament\Actions\Action;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use RuntimeException;

class OrgMessagesTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('locale')->label(__('Language'))->badge()->sortable(),
                TextColumn::make('key')->label(__('Message'))->searchable()->sortable(),
                TextColumn::make('body')->label(__('Says'))->limit(80)->searchable(),
            ])
            ->defaultSort('key')
            ->headerActions([self::rewordAction()])
            ->recordActions([self::removeAction()])
            ->emptyStateHeading(__('Nothing has been reworded'))
            ->emptyStateDescription(__('Your pages and mail say what the catalogue says.'));
    }

    private static function rewordAction(): Action
    {
        return Action::make('reword')
            ->label(__('Reword a message'))
            ->icon('heroicon-m-language')
            ->visible(fn (): bool => SignariSignIn::may('organizations:write'))
            ->schema([
                TextInput::make('locale')->label(__('Language'))->required()->default('en')
                    ->helperText(__('A language this deployment renders, such as en or ar.')),
                TextInput::make('key')->label(__('Message'))->required()
                    ->helperText(__('Its key: `signari i18n keys` prints every one.')),
                Textarea::make('text')->label(__('Says'))->required()->maxLength(2000)
                    ->helperText(__('Plain text. Markup is shown as text.')),
            ])
            ->action(function (array $data, $livewire): void {
                $orgId = auth()->user()?->org_id;
                if (blank($orgId)) {
                    Notification::make()->title(__('You are not assigned to an organisation'))->danger()->send();

                    return;
                }
                try {
                    EngineAdminApi::fromConfig()->asOf($livewire->renderedConfigVersion ?? null)
                        ->setOrganisationMessage($orgId, $data['locale'], $data['key'], $data['text']);
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title(__('Message reworded'))->success()->send();
            });
    }

    private static function removeAction(): Action
    {
        return Action::make('remove')
            ->label(__('Use the catalogue\'s'))
            ->color('gray')
            ->requiresConfirmation()
            ->visible(fn (): bool => SignariSignIn::may('organizations:write'))
            ->action(function (OrgMessage $record, $livewire): void {
                $orgId = auth()->user()?->org_id;
                if (blank($orgId)) {
                    Notification::make()->title(__('You are not assigned to an organisation'))->danger()->send();

                    return;
                }
                try {
                    EngineAdminApi::fromConfig()->asOf($livewire->renderedConfigVersion ?? null)
                        ->removeOrganisationMessage($orgId, $record->locale, $record->key);
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title(__('Message restored'))->success()->send();
            });
    }
}
