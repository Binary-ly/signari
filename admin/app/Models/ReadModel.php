<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use RuntimeException;

/**
 * A row of a core_v1 view. Every write goes through the engine's Admin API, so
 * one reaching this is a bug that should say so rather than a query that fails
 * on a missing grant.
 */
abstract class ReadModel extends Model
{
    public $timestamps = false;

    public function save(array $options = []): bool
    {
        throw new RuntimeException(static::class.' is a read model: the console writes through the Admin API.');
    }
}
