<?php

namespace App\Models;

class ClaimMapper extends ReadModel
{
    protected $table = 'core_v1.claim_mappers';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = ['created_at' => 'datetime'];
}
