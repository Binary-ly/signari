<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.radius_clients.
 *
 * Network devices permitted to send Access-Requests. The shared secret is never
 * here and is never anywhere readable: it is sealed with the root key, because
 * RADIUS needs the secret itself to verify a request rather than a hash of it.
 *
 * `network` is part of the credential, not a convenience. RADIUS has no
 * handshake and no certificate, so the source address and the secret are the
 * only two things distinguishing a real switch from anybody who can send a UDP
 * packet.
 */
class RadiusClient extends Model
{
    protected $table = 'core_v1.radius_clients';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $casts = [
        'enabled'    => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'RADIUS clients are registered with `signari radius add-client`. The '.
            'shared secret is sealed with the root key and never passes through here.'
        );
    }
}
