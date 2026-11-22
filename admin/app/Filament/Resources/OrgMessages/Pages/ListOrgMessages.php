<?php

namespace App\Filament\Resources\OrgMessages\Pages;

use App\Filament\Concerns\CarriesConfigVersion;
use App\Filament\Resources\OrgMessages\OrgMessageResource;
use Filament\Resources\Pages\ListRecords;

class ListOrgMessages extends ListRecords
{
    use CarriesConfigVersion;

    protected static string $resource = OrgMessageResource::class;
}
