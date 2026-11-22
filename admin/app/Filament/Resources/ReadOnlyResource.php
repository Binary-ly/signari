<?php

namespace App\Filament\Resources;

use App\Services\SignariSignIn;
use Filament\Resources\Resource;

/**
 * A screen over a core_v1 view that nothing is created on. The policy under the
 * view narrows it to the operator's organisation.
 */
abstract class ReadOnlyResource extends Resource
{
    /** What an operator signed in through Signari needs to see this screen. */
    protected static string $readScope = 'config:read';

    public static function canViewAny(): bool
    {
        return SignariSignIn::may(static::$readScope);
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }
}
