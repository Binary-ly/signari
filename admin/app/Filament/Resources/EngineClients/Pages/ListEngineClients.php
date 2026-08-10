<?php

namespace App\Filament\Resources\EngineClients\Pages;

use App\Filament\Resources\EngineClients\EngineClientResource;
use Filament\Resources\Pages\ListRecords;

class ListEngineClients extends ListRecords
{
    protected static string $resource = EngineClientResource::class;

    protected function getHeaderActions(): array
    {
        // Registering a client is a write to schema core; it goes through the
        // engine Admin API, not this panel (ADR-004).
        return [];
    }
}
