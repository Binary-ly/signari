<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.admin_tokens.
 *
 * Admin API tokens for this organisation.
 *
 * The secret is never here. It is stored as a SHA-256 and shown once at
 * creation; no path in this system reveals it afterwards.
 *
 * Deployment-wide tokens (org_id NULL) are deliberately NOT visible: listing
 * one for a tenant would disclose that another tenant is reachable with it.
 */
class AdminToken extends Model
{
    protected $table = 'core_v1.admin_tokens';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'scopes' => 'array',
        'created_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'last_used_at' => 'datetime',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'This is configuration the engine owns. The console reads it; it is '.
            'changed with the signari CLI or through the engine Admin API.'
        );
    }
}
