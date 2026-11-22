<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.authorization_models.
 *
 * The file an operator wrote, as they wrote it, for the same reason as the
 * access policy: it is reviewed as a file. No model means nothing is permitted,
 * which the empty state says, because an application asking would be told no
 * and nobody would know why.
 */
class AuthorizationModel extends Model
{
    protected $table = 'core_v1.authorization_models';

    protected $primaryKey = 'org_id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'updated_at' => 'datetime',
        'line_count' => 'integer',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'The model is set with `signari authz set-model`, which runs its own '.
            'tests first. Editing it here would skip that.'
        );
    }
}
