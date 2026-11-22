<?php

use App\Support\RedirectTo;
use App\Support\SignariClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Jumbojett\OpenIDConnectClientException;

Route::get('/', fn () => '<p><a href="/login">Sign in with Signari</a></p>');

// The redirect out: the client makes the state, nonce and PKCE verifier, keeps them in
// the session, and asks for the browser to be sent to the authorization endpoint.
Route::get('/login', function () {
    try {
        SignariClient::make()->authenticate();
    } catch (RedirectTo $to) {
        return redirect()->away($to->url);
    }

    return response('the client did not ask to sign in', 500);
});

// The callback. The state is checked here first: the library compares it only after it
// has spent the code at the token endpoint, and a code nobody here asked for should not
// be redeemed at all. Then the library exchanges the code with the verifier, checks the
// ID token's signature against the published keys, and its issuer, audience, expiry and
// nonce.
Route::get('/callback', function (Request $request) {
    $client = SignariClient::make();
    $held = $client->heldState();
    if ($held === null || ! hash_equals($held, (string) $request->query('state'))) {
        return response('this sign-in was not started in this browser, or it took too long', 400);
    }
    try {
        $client->authenticate();
    } catch (OpenIDConnectClientException $e) {
        // The server's own words, which docs/troubleshooting.md explains.
        return response('the sign-in was refused: '.e($e->getMessage()), 400);
    }
    $who = $client->getVerifiedClaims('email') ?? $client->getVerifiedClaims('sub');

    return '<p>Signed in as '.e($who).'</p>';
});
