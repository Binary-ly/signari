<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.access_policies.
 *
 * The policy is a YAML document an operator wrote, applied verbatim — that is
 * the design, so it can be version-controlled and reviewed in a pull request
 * rather than assembled by clicking. The console shows the document, not a
 * reconstruction of it.
 *
 * No policy at all means every client is open to every user. That may be
 * correct; it should be a decision rather than a surprise, which is why the
 * empty state says so.
 */
class AccessPolicy extends Model
{
    protected $table = 'core_v1.access_policies';

    protected $primaryKey = 'org_id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'applied_at'        => 'datetime',
        'line_count'        => 'integer',
        'document_bytes'    => 'integer',
        'denies_by_default' => 'boolean',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'The policy is applied with `signari policy apply`, which runs the '.
            'document’s own tests first. Editing it here would skip that.'
        );
    }
}
