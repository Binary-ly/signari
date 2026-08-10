<?php

namespace App\Filament\Resources\EngineUsers\Pages;

use App\Filament\Resources\EngineUsers\EngineUserResource;
use Filament\Resources\Pages\ListRecords;

class ListEngineUsers extends ListRecords
{
    protected static string $resource = EngineUserResource::class;

    protected function getHeaderActions(): array
    {
        // Nothing here. Creating a user is a write to schema core, which the
        // admin role cannot perform (ADR-004); it goes through the engine API.
        return [];
    }
}
