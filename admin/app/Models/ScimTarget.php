<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.scim_targets.
 *
 * SCIM provisioning targets.
 *
 * `dry_run` is the field that catches people: a target in dry run looks
 * configured, reports no errors, and writes nothing to the downstream
 * application. `pending_deactivations` is how many users are supposed to be
 * gone from it and are not yet.
 */
class ScimTarget extends Model
{
    protected $table = 'core_v1.scim_targets';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'enabled' => 'boolean',
        'dry_run' => 'boolean',
        'linked_users' => 'integer',
        'pending_deactivations' => 'integer',
        'last_synced_at' => 'datetime',
        'created_at' => 'datetime',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'This is configuration the engine owns. The console reads it; it is '.
            'changed with the signari CLI or through the engine Admin API.'
        );
    }
}
