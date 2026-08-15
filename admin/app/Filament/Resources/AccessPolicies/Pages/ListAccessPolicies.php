<?php

namespace App\Filament\Resources\AccessPolicies\Pages;

use App\Filament\Resources\AccessPolicies\AccessPolicyResource;
use Filament\Resources\Pages\ListRecords;

class ListAccessPolicies extends ListRecords
{
    protected static string $resource = AccessPolicyResource::class;
}
