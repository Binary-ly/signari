<?php

namespace App\Models;

class EngineSession extends ReadModel
{
    protected $table = 'core_v1.sessions';

    protected $primaryKey = 'sid';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = [
        'auth_time' => 'datetime',
        'not_after' => 'datetime',
        'revoked_at' => 'datetime',
        'is_live' => 'boolean',
        'amr' => 'array',
    ];
}
