<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.relations: a subject holding a relation on an object.
 *
 * Only the live ones, because a decision reads no others. A row here says
 * somebody holds this directly; a relation held through a parent or a team has
 * no row naming them, and the console says so rather than implying this is
 * everybody who may act.
 */
class Relation extends Model
{
    protected $table = 'core_v1.relations';

    public $timestamps = false;

    protected $casts = [
        'granted_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'Relations are written through the Admin API, by the application or '.
            '`signari authz grant`. The console has no write path to them.'
        );
    }
}
