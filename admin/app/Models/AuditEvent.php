<?php

namespace App\Models;

class AuditEvent extends ReadModel
{
    protected $table = 'core_v1.audit_events';

    protected $casts = ['occurred_at' => 'datetime', 'detail' => 'array'];
}
