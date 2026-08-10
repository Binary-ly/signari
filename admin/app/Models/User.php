<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Database\Factories\UserFactory;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * A console operator.
 *
 * Not an end user of the identity provider -- those live in core.users behind
 * core_v1.users and are read-only here (see EngineUser). This table exists only
 * for the handful of people who administer the thing, which is why membership in
 * it is itself the authorisation to reach the panel.
 */
#[Fillable(['name', 'email', 'password'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable implements FilamentUser
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;

    /**
     * Filament denies panel access outside `local` unless this contract is
     * implemented, so without it the console is unreachable in production while
     * working perfectly on the developer's machine -- a failure that shows up
     * exactly once, at the worst moment.
     *
     * Access is NOT tenant scoping and must not be confused with it. Reaching the
     * panel says only "you are an operator"; WHICH rows you then see is decided by
     * ScopeToOrganisation and enforced by row-level security in PostgreSQL. An
     * operator with no organisation assigned gets in and sees nothing, which is
     * the intended fail-closed shape.
     */
    public function canAccessPanel(Panel $panel): bool
    {
        return true;
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
