<?php

namespace App\Filament\Resources\LogoutDeliveries;

use App\Filament\Resources\LogoutDeliveries\Pages\ListLogoutDeliveries;
use App\Filament\Resources\LogoutDeliveries\Tables\LogoutDeliveriesTable;
use App\Models\LogoutDelivery;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

class LogoutDeliveryResource extends Resource
{
    protected static ?string $model = LogoutDelivery::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedArrowRightStartOnRectangle;

    // Accessors rather than static properties: PHP cannot call __() in a
    // property initialiser. See AccessPolicyResource.

    public static function getNavigationLabel(): string
    {
        return __('Logout delivery');
    }

    public static function getModelLabel(): string
    {
        return __('logout delivery');
    }

    /**
     * The count of PARKED deliveries, not of all rows. A badge showing "1,204
     * logouts" is noise; one showing "3" next to a red dot is the number an
     * operator has to act on.
     */
    public static function getNavigationBadge(): ?string
    {
        $parked = LogoutDelivery::query()->where('status', 'parked')->count();

        return $parked > 0 ? (string) $parked : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'danger';
    }

    public static function table(Table $table): Table
    {
        return LogoutDeliveriesTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListLogoutDeliveries::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
