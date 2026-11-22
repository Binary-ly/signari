<?php

namespace App\Filament\Resources\AuthorizationModels\Pages;

use App\Filament\Resources\AuthorizationModels\AuthorizationModelResource;
use Filament\Resources\Pages\ListRecords;

class ListAuthorizationModels extends ListRecords
{
    protected static string $resource = AuthorizationModelResource::class;
}
