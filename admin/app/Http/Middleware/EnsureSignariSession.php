<?php

namespace App\Http\Middleware;

use App\Services\SignariSignIn;
use Closure;
use Filament\Facades\Filament;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * An operator who signed in through Signari is held to that sign-in on every
 * console request (6.06), Livewire's included.
 *
 * The engine is asked who the operator's token is for (GET /admin/me). It reads
 * the Signari session, the person, the console client's designation and the
 * roles on that request (ADR-007), so revoking the session in Signari,
 * deactivating the person or taking their role away signs them out of the
 * console on their next click. The organisation the console is scoped to is the
 * one the engine names, written onto the operator before ScopeToOrganisation
 * reads it.
 *
 * Fails closed: with Signari unreachable the request is refused, not served on
 * the strength of a sign-in nothing can confirm. A break-glass account is
 * exempt; it is the way in when Signari is what is down. Once Signari sign-in
 * is configured, any other operator without a live Signari sign-in -- a local
 * account from before, signed in with a password -- is signed out here.
 */
class EnsureSignariSession
{
    public function __construct(private readonly SignariSignIn $signIn) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = Auth::user();
        if ($user === null || ! SignariSignIn::configured() || $user->break_glass) {
            return $next($request);
        }

        try {
            $me = $this->signIn->current();
        } catch (RuntimeException $e) {
            Log::error('confirming a console sign-in with Signari', ['error' => $e->getMessage()]);
            abort(503, __('Signari cannot be reached to confirm your sign-in. Try again shortly.'));
        }

        $ended = $me === null || $user->signari_user_id === null || ($me['user']['id'] ?? null) !== $user->signari_user_id;
        if ($ended || empty($me['scopes'])) {
            $this->signIn->forget();
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect()->to(Filament::getPanel('admin')->getLoginUrl())
                ->with('signari_error', $ended ? __('Your Signari sign-in has ended. Sign in again.')
                    : __('You hold no administrative role in Signari.'));
        }
        // What the operator's roles allow on this request, for the screens
        // to read (SignariSignIn::may).
        $request->session()->put(SignariSignIn::ME, $me);

        $orgId = $me['org_id'] ?? null;
        if ($user->org_id !== $orgId) {
            $user->forceFill(['org_id' => $orgId])->saveQuietly();
        }

        return $next($request);
    }
}
