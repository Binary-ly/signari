<?php

namespace App\Filament\Concerns;

use Illuminate\Support\Facades\DB;
use Livewire\Attributes\Locked;

/**
 * The configuration version a page was rendered from, carried to its writes.
 *
 * Read on every render, before the table reads its rows, so the version is
 * never newer than what the operator is looking at: a change that commits
 * between the two reads moves the version past the one carried, and the write
 * is refused rather than made over it. A write sends it as If-Match, so a form
 * opened before somebody else's change cannot overwrite that change unseen,
 * however long it was open. Until October 2026 the console read the version
 * immediately before each write instead, which caught only two saves in the
 * same moment, and a stale form won.
 *
 * Locked, because the browser holds the component's state between requests
 * and must not be able to move the precondition its own write is held to.
 */
trait CarriesConfigVersion
{
    #[Locked]
    public ?int $renderedConfigVersion = null;

    public function renderingCarriesConfigVersion(): void
    {
        $version = DB::table('core_v1.config_status')->value('version');
        $this->renderedConfigVersion = $version === null ? null : (int) $version;
    }
}
