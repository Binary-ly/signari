<?php

namespace App\Models;

class ScimSource extends ReadModel
{
    protected $table = 'core_v1.scim_sources';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = ['enabled' => 'boolean', 'last_seen_at' => 'datetime', 'created_at' => 'datetime'];
}
