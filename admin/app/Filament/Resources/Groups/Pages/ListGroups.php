<?php

namespace App\Filament\Resources\Groups\Pages;

use App\Filament\Concerns\CarriesConfigVersion;
use App\Filament\Resources\Groups\GroupResource;
use Filament\Resources\Pages\ListRecords;

class ListGroups extends ListRecords
{
    use CarriesConfigVersion;

    protected static string $resource = GroupResource::class;
}
