<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.saml_providers.
 *
 * Registered SAML service providers. `config_state` names the
 * half-configurations -- a provider that requires signed AuthnRequests with
 * no certificate on file refuses every login, and looks fine in every
 * individual column.
 */
class SamlProvider extends Model
{
    protected $table = 'core_v1.saml_providers';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'enabled' => 'boolean',
        'want_authn_requests_signed' => 'boolean',
        'has_signing_cert' => 'boolean',
        'assertions_encrypted' => 'boolean',
        'acs_url_count' => 'integer',
        'lifetime_seconds' => 'integer',
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
