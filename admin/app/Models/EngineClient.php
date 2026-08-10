<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.clients.
 *
 * Same rules as EngineUser: reads through the versioned view, writes refused at
 * the model because the admin has no privilege on schema core (ADR-004).
 *
 * Note what the view deliberately does NOT expose: client_secret_hash. A secret
 * hash has no reason to cross into the admin plane, and the surest way to keep it
 * out of a screenshot, a log, or a CSV export is for it never to arrive.
 */
class EngineClient extends Model
{
    protected $table = 'core_v1.clients';

    protected $primaryKey = 'client_id';

    protected $keyType = 'string';

    public $incrementing = false;

    public $timestamps = false;

    protected $casts = [
        'enabled'             => 'boolean',
        'require_pkce'        => 'boolean',
        'grant_types'         => 'array',
        'response_types'      => 'array',
        'scopes'              => 'array',
        'redirect_uris'       => 'array',
        'access_token_ttl_s'  => 'integer',
        'refresh_token_ttl_s' => 'integer',
        'created_at'          => 'datetime',
        'updated_at'          => 'datetime',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(self::writeMessage('save'));
    }

    public function delete(): bool
    {
        throw new RuntimeException(self::writeMessage('delete'));
    }

    public static function create(array $attributes = [])
    {
        throw new RuntimeException(self::writeMessage('create'));
    }

    private static function writeMessage(string $op): string
    {
        return sprintf(
            'EngineClient::%s() is not permitted. The admin has no write access to schema '.
            'core (ADR-004); client changes go through the engine Admin API.',
            $op
        );
    }

    /**
     * A public client with PKCE disabled has no client authentication at all --
     * anyone holding the client_id can redeem a code. Worth surfacing loudly
     * rather than leaving an operator to infer it from two separate columns.
     */
    public function isUnauthenticated(): bool
    {
        return $this->client_type === 'public' && ! $this->require_pkce;
    }

    /**
     * Back-channel logout is the only logout mechanism that still works now that
     * browsers block third-party cookies. A client without an endpoint cannot be
     * told its user signed out.
     */
    public function canReceiveLogout(): bool
    {
        return ! empty($this->backchannel_logout_uri);
    }
}
