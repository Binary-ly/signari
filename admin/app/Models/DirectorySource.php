<?php

namespace App\Models;

class DirectorySource extends ReadModel
{
    protected $table = 'core_v1.directory_sources';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = [
        'enabled' => 'boolean',
        'dry_run' => 'boolean',
        'last_sync_at' => 'datetime',
        'next_sync_at' => 'datetime',
    ];
}
