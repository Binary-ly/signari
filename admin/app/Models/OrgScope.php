<?php

namespace App\Models;

class OrgScope extends ReadModel
{
    protected $table = 'core_v1.scopes';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = ['advertise' => 'boolean', 'created_at' => 'datetime'];
}
