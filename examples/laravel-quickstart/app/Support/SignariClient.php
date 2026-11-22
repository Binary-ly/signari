<?php

namespace App\Support;

use Jumbojett\OpenIDConnectClient;

/**
 * The OpenID Connect client this application signs people in with, made to live inside
 * Laravel: its state, nonce and PKCE verifier are kept in Laravel's session, not PHP's
 * own, and a redirect is handed back to the route as a response instead of sending a
 * header and exiting, which would skip saving that session. See docs/quickstart-laravel.md.
 */
class SignariClient extends OpenIDConnectClient
{
    public static function make(): self
    {
        $c = config('signari');
        $client = new self($c['issuer'], $c['client_id'], $c['client_secret'] ?: null);
        $client->setRedirectURL($c['redirect_uri']);
        $client->addScope(['openid', 'email', 'profile']);
        // Signari requires PKCE of every client, confidential ones included, and S256 only.
        $client->setCodeChallengeMethod('S256');
        if (! empty($c['ca_file'])) {
            // A certificate this machine does not trust, as on a laptop. Never turn
            // certificate checking off instead.
            $client->setCertPath($c['ca_file']);
        }

        return $client;
    }

    /** The redirect out, as a response for the route to return. */
    public function redirect(string $url): void
    {
        throw new RedirectTo($url);
    }

    /** The state this browser was sent away with, or null. */
    public function heldState(): ?string
    {
        $state = $this->getSessionKey('openid_connect_state');

        return is_string($state) ? $state : null;
    }

    protected function startSession(): void {}

    protected function commitSession(): void {}

    protected function getSessionKey(string $key)
    {
        return session()->get('signari.'.$key, false);
    }

    protected function setSessionKey(string $key, $value): void
    {
        session()->put('signari.'.$key, $value);
    }

    protected function unsetSessionKey(string $key): void
    {
        session()->forget('signari.'.$key);
    }
}
