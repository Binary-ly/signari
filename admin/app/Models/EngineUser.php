<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.users.
 *
 * This is the shape ADR-004 forces and ADR-006 constrains: the admin cannot touch
 * `core` at all, so Eloquent is pointed at the versioned read-only view instead.
 * The view is a contract the engine holds stable while the physical tables move
 * underneath it -- which is also how the engine performs zero-downtime migrations.
 *
 * EVERY write path is disabled at the model level. The database will refuse them
 * anyway (signari_admin has no privilege on core, and a view is not updatable here),
 * but a PDO permission error surfacing from deep inside Filament is a poor way to
 * learn about an architectural rule. Failing here says what the rule IS.
 *
 * Writes go through the engine's Admin API. There is no exception, including
 * "just this one script".
 */
class EngineUser extends Model
{
    protected $table = 'core_v1.users';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    // The view exposes no updated_at/created_at pair Eloquent can manage.
    public $timestamps = false;

    protected $casts = [
        'email_verified_at'   => 'datetime',
        'created_at'          => 'datetime',
        'updated_at'          => 'datetime',
        'has_password'        => 'boolean',
        'password_is_current' => 'boolean',
        'totp_enabled'        => 'boolean',
        'passkey_count'       => 'integer',
    ];

    /**
     * Guard rails. Each of these is what Eloquent would otherwise happily attempt.
     */
    public function save(array $options = []): bool
    {
        throw new RuntimeException(self::writeMessage('save'));
    }

    public function delete(): bool
    {
        throw new RuntimeException(self::writeMessage('delete'));
    }

    public function forceDelete(): bool
    {
        throw new RuntimeException(self::writeMessage('forceDelete'));
    }

    public static function create(array $attributes = [])
    {
        throw new RuntimeException(self::writeMessage('create'));
    }

    private static function writeMessage(string $op): string
    {
        return sprintf(
            'EngineUser::%s() is not permitted. The admin has no write access to schema '.
            'core (ADR-004); user changes go through the engine Admin API.',
            $op
        );
    }

    /**
     * Whether this user still needs a password rehash after being imported from
     * another provider. Drives the migration dashboard: the interesting number
     * during a migration is how many users have NOT yet signed in.
     */
    public function needsRehash(): bool
    {
        return $this->has_password && ! $this->password_is_current;
    }

    /**
     * Passwordless-capable: at least two passkeys registered.
     *
     * Two, not one. A single passkey means losing that device locks the account
     * out, so it is not a safe basis for removing the password.
     */
    public function canGoPasswordless(): bool
    {
        return $this->passkey_count >= 2;
    }
}
