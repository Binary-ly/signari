<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.identity_providers.
 *
 * External sign-in providers (Google, GitHub, Microsoft, generic OIDC).
 *
 * `trust_email_verification` is the one worth reading twice: a generic OIDC
 * provider that allows sign-up without it refuses every sign-up, because
 * accounts are matched on (provider, subject) and never on email.
 */
class IdentityProvider extends Model
{
    protected $table = 'core_v1.identity_providers';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'enabled' => 'boolean',
        'allow_signup' => 'boolean',
        'allow_linking' => 'boolean',
        'trust_email_verification' => 'boolean',
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
