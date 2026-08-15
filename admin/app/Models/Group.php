<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.groups.
 *
 * Groups and their membership counts.
 *
 * `released_to_clients` and `released_to_saml` matter before renaming one:
 * releases name groups by NAME, so a rename silently removes the group from
 * every allow-list that mentioned it.
 */
class Group extends Model
{
    protected $table = 'core_v1.groups';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'member_count' => 'integer',
        'released_to_clients' => 'integer',
        'released_to_saml' => 'integer',
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
