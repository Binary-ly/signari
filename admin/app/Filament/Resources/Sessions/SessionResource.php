<?php

namespace App\Filament\Resources\Sessions;

use App\Filament\Resources\ReadOnlyResource;
use App\Filament\Resources\Sessions\Pages\ListSessions;
use App\Models\EngineSession;
use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use RuntimeException;

/** Who is signed in. The engine ends a session; this asks it to. */
class SessionResource extends ReadOnlyResource
{
    protected static string $readScope = 'users:read';

    protected static ?string $model = EngineSession::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedComputerDesktop;

    public static function getNavigationGroup(): ?string
    {
        return __('Activity');
    }

    public static function getNavigationLabel(): string
    {
        return __('Sessions');
    }

    public static function getModelLabel(): string
    {
        return __('session');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Sessions');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('user_id')->label(__('Person')),
                TextColumn::make('auth_time')->label(__('Signed in'))->dateTime()->sortable(),
                TextColumn::make('amr')->label(__('How'))->badge(),
                TextColumn::make('not_after')->label(__('Ends'))->dateTime(),
                IconColumn::make('is_live')->label(__('Live'))->boolean(),
                TextColumn::make('user_agent')->label(__('Browser'))->limit(40)->placeholder('—')
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->recordActions([self::endAction()])
            ->defaultSort('auth_time', 'desc')
            ->emptyStateHeading(__('Nobody is signed in'));
    }

    private static function endAction(): Action
    {
        return Action::make('end')
            ->label(__('End session'))
            ->color('danger')
            ->requiresConfirmation()
            ->visible(fn (EngineSession $record): bool => $record->is_live && SignariSignIn::may('users:write'))
            ->action(function (EngineSession $record, $livewire): void {
                try {
                    EngineAdminApi::fromConfig()->asOf($livewire->renderedConfigVersion ?? null)->endSession($record->sid);
                } catch (RuntimeException $e) {
                    Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                        ->danger()->persistent()->send();

                    return;
                }
                Notification::make()->title(__('Session ended'))->success()->send();
            });
    }

    public static function getPages(): array
    {
        return ['index' => ListSessions::route('/')];
    }
}
