<?php

namespace App\Http\Middleware;

use App\Services\SignariSignIn;
use Closure;
use Filament\Auth\MultiFactor\Http\Middleware\EnsureMultiFactorAuthenticationIsEnabled;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * The panel's required second factor (AdminPanelProvider), for each kind of
 * operator (6.06).
 *
 * An operator signed in through Signari proved theirs there: the sign-in asked
 * for acr 2, and the engine refuses their token at the Admin API, on every
 * request, unless their session proved a second factor. Asking them to enrol a
 * console TOTP as well would be a second factor nobody else checks. A local
 * account -- break-glass, or every operator where Signari sign-in is not
 * configured -- is held to the console's own, as before.
 */
class EnsureSecondFactor
{
    public function __construct(private readonly EnsureMultiFactorAuthenticationIsEnabled $local) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $user = Auth::user();
        if ($user !== null && SignariSignIn::configured() && ! $user->break_glass
            && $user->signari_user_id !== null && session()->has(SignariSignIn::SESSION)) {
            return $next($request);
        }

        return $this->local->handle($request, $next);
    }
}
