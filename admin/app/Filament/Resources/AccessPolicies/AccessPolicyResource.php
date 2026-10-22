<?php

namespace App\Filament\Resources\AccessPolicies;

use App\Filament\Resources\AccessPolicies\Pages\ListAccessPolicies;
use App\Filament\Resources\AccessPolicies\Tables\AccessPoliciesTable;
use App\Models\AccessPolicy;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

/**
 * The access policy document currently in force.
 *
 * Read-only. The console has no privilege on schema core (ADR-004); this is
 * written with the signari CLI.
 */
class AccessPolicyResource extends Resource
{
    protected static ?string $model = AccessPolicy::class;

    /** What an operator signed in through Signari needs to see this screen (6.06). */
    public static function canViewAny(): bool
    {
        return SignariSignIn::may('config:read');
    }

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedDocumentText;

    /*
     * Methods rather than static properties, because PHP will not evaluate a
     * function call in a property initialiser -- so a label written as
     * `= 'Access policy'` can never be translated. Filament reads these
     * accessors, which is what makes the difference invisible to it.
     */

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('Access policy');
    }

    public static function getModelLabel(): string
    {
        return __('access policy');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Access policy');
    }


    public static function table(Table $table): Table
    {
        return AccessPoliciesTable::configure($table);
    }

    public static function getPages(): array
    {
        return ['index' => ListAccessPolicies::route('/')];
    }

    public static function canCreate(): bool
    {
        return false;
    }
}
