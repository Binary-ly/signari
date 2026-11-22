<?php

namespace App\Filament\Resources\OrgMessages;

use App\Filament\Resources\OrgMessages\Pages\ListOrgMessages;
use App\Filament\Resources\OrgMessages\Tables\OrgMessagesTable;
use App\Models\OrgMessage;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * What the organisation's pages and mail say where it has reworded them.
 *
 * Read from the view; written through the engine, which refuses a key nothing
 * renders and escapes the text on the way to a page.
 */
class OrgMessageResource extends Resource
{
    protected static ?string $model = OrgMessage::class;

    /** What an operator signed in through Signari needs to see this screen (6.06). */
    public static function canViewAny(): bool
    {
        return SignariSignIn::may('config:read');
    }

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedLanguage;

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('Messages');
    }

    public static function getModelLabel(): string
    {
        return __('message');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Messages');
    }

    public static function table(Table $table): Table
    {
        return OrgMessagesTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListOrgMessages::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
