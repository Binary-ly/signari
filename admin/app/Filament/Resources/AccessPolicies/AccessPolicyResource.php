<?php

namespace App\Filament\Resources\AccessPolicies;

use App\Filament\Resources\AccessPolicies\Pages\ListAccessPolicies;
use App\Filament\Resources\AccessPolicies\Tables\AccessPoliciesTable;
use App\Models\AccessPolicy;
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

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedDocumentText;

    protected static string|\UnitEnum|null $navigationGroup = 'Configuration';

    protected static ?string $navigationLabel = 'Access policy';

    protected static ?string $modelLabel = 'access policy';

    protected static ?string $pluralModelLabel = 'Access policy';


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
