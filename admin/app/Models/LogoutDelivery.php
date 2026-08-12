<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * Read model over core_v1.logout_deliveries.
 *
 * The answer to "did signing out actually work?" -- a question almost no
 * identity provider can answer about itself. The engine queues a back-channel
 * logout notice for every relying party that saw a session; this is what
 * happened to each one.
 *
 * A `parked` row is not a warning. It is a specific person who believes they
 * signed out of a specific application and did not.
 */
class LogoutDelivery extends Model
{
    protected $table = 'core_v1.logout_deliveries';

    protected $primaryKey = 'id';

    public $timestamps = false;

    protected $casts = [
        'queued_at'       => 'datetime',
        'delivered_at'    => 'datetime',
        'next_attempt_at' => 'datetime',
        'attempts'        => 'integer',
    ];

    public function save(array $options = []): bool
    {
        throw new RuntimeException(
            'Delivery state belongs to the engine. The console reads it; it does not write it.'
        );
    }

    /** Parked means the retry budget is gone and nobody is coming back to it. */
    public function isParked(): bool
    {
        return $this->status === 'parked';
    }

    /**
     * A relying party with no back-channel endpoint registered cannot be told
     * anything. Worth distinguishing from a delivery that failed: one is a
     * configuration gap, the other is an outage.
     */
    public function isUnreachable(): bool
    {
        return blank($this->backchannel_logout_uri);
    }
}
