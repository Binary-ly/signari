<?php

namespace App\Filament\Resources\ScimSources\Pages;

use App\Filament\Resources\ScimSources\ScimSourceResource;
use Filament\Resources\Pages\ListRecords;

class ListScimSources extends ListRecords
{
    protected static string $resource = ScimSourceResource::class;
}
