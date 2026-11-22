<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.org_messages: one catalogue message reworded by the
 * organisation, in one language. The view's id is the language and the key.
 */
class OrgMessage extends Model
{
    protected $table = 'core_v1.org_messages';

    protected $keyType = 'string';

    public $incrementing = false;

    public $timestamps = false;

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'Messages are written through the Admin API, which refuses a key nothing '.
            'renders. The console has no database write path to them.'
        );
    }
}
