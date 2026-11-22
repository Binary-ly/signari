<?php

namespace App\Models;

class AttributeDefinition extends ReadModel
{
    protected $table = 'core_v1.attribute_schema';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $casts = [
        'personal' => 'boolean',
        'user_readable' => 'boolean',
        'user_writable' => 'boolean',
        'required' => 'boolean',
        'created_at' => 'datetime',
    ];
}
