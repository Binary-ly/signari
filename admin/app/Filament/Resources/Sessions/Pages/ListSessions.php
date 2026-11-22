<?php

namespace App\Filament\Resources\Sessions\Pages;

use App\Filament\Concerns\CarriesConfigVersion;
use App\Filament\Resources\Sessions\SessionResource;
use Filament\Resources\Pages\ListRecords;

class ListSessions extends ListRecords
{
    use CarriesConfigVersion;

    protected static string $resource = SessionResource::class;
}
