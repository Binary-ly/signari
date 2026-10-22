<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\SignariSignIn;
use App\Services\SignInRefused;
use Filament\Facades\Filament;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

/**
 * The two ends of signing in through Signari (6.06): the redirect out, and the
 * callback that finishes it. See SignariSignIn.
 */
class SignariSignInController
{
    public function redirect(SignariSignIn $signIn): RedirectResponse
    {
        abort_unless(SignariSignIn::configured(), 404);

        return redirect()->away($signIn->begin());
    }

    public function callback(Request $request, SignariSignIn $signIn): RedirectResponse
    {
        abort_unless(SignariSignIn::configured(), 404);
        $panel = Filament::getPanel('admin');

        if ($request->has('error') || ! $request->filled('code')) {
            return redirect()->to($panel->getLoginUrl())
                ->with('signari_error', __('Signari did not sign you in. Start again.'));
        }
        try {
            $me = $signIn->complete((string) $request->query('state'), (string) $request->query('code'));
        } catch (SignInRefused $e) {
            return redirect()->to($panel->getLoginUrl())->with('signari_error', $e->getMessage());
        }

        // Found by the person's id in Signari, never by address (see the
        // migration): the console row is theirs because Signari says so.
        $user = User::query()->firstOrNew(['signari_user_id' => $me['user']['id']]);
        $user->forceFill([
            'signari_user_id' => $me['user']['id'],
            'name' => $me['user']['display_name'] ?: ($me['user']['email'] ?: 'Signari operator'),
            // Not their address: the console's addresses are unique and its
            // own, and one shared with a local account must not make them one.
            'email' => $me['user']['id'].'@signari.invalid',
            'org_id' => $me['org_id'] ?? null,
            'break_glass' => false,
        ]);
        if (! $user->exists) {
            // No password signs this account in: it has none anybody knows.
            $user->password = Str::random(64);
        }
        $user->save();

        Auth::login($user);
        $request->session()->regenerate();

        return redirect()->intended($panel->getUrl());
    }
}
