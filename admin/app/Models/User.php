<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use App\Services\SignariSignIn;
use Database\Factories\UserFactory;
use Filament\Auth\MultiFactor\App\Concerns\InteractsWithAppAuthentication;
use Filament\Auth\MultiFactor\App\Concerns\InteractsWithAppAuthenticationRecovery;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthentication;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthenticationRecovery;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SensitiveParameter;

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
class User extends Authenticatable implements FilamentUser, HasAppAuthentication, HasAppAuthenticationRecovery
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;

    /*
     * The second factor the panel requires (AdminPanelProvider). The traits
     * store the TOTP secret and recovery codes encrypted and hidden from
     * serialisation.
     */
    use InteractsWithAppAuthentication {
        saveAppAuthenticationSecret as private storeAppAuthenticationSecret;
    }
    use InteractsWithAppAuthenticationRecovery;

    /**
     * Setting up, replacing or removing the second factor ends every other
     * session this operator holds and every remember-me cookie issued before.
     *
     * They survived it. A session opened, or a remember-me cookie minted, with
     * a password alone kept working after the operator enrolled -- so whoever
     * had the password before enrolment kept a console session that the second
     * factor was meant to have made impossible. The session this request runs
     * in is kept: it is the operator who just proved the factor.
     *
     * Sessions are rows in the sessions table with SESSION_DRIVER=database, the
     * console's default; with another driver only the remember-me cookies are
     * ended here, and that is said in docs/console-configuration.md.
     */
    public function saveAppAuthenticationSecret(#[SensitiveParameter] ?string $secret): void
    {
        $this->storeAppAuthenticationSecret($secret);

        $this->setRememberToken(Str::random(60));
        $this->saveQuietly();

        if (config('session.driver') === 'database') {
            DB::connection(config('session.connection'))
                ->table(config('session.table', 'sessions'))
                ->where('user_id', $this->getKey())
                ->where('id', '!=', session()->getId())
                ->delete();
        }
    }

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
     *
     * Once Signari sign-in is configured (6.06), only two kinds of operator
     * reach it: one signed in through Signari, whose sign-in
     * EnsureSignariSession confirms with the engine on every request, and a
     * break-glass account. A local account from before is neither, and a
     * password no longer admits it.
     */
    public function canAccessPanel(Panel $panel): bool
    {
        if (! SignariSignIn::configured()) {
            return true;
        }

        return $this->break_glass
            || ($this->signari_user_id !== null && session()->has(SignariSignIn::SESSION));
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
            'break_glass' => 'boolean',
        ];
    }
}
