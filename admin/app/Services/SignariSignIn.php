<?php

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Signing in to the console through Signari itself (6.06).
 *
 * The authorization code flow with PKCE against the issuer, for the console's
 * own client, asking for a second factor (acr_values=2) and the Admin API's
 * audience (<issuer>/admin, RFC 8707). Who signed in is then asked of the
 * Admin API, GET /admin/me, with the token just issued: the engine verifies it
 * and answers with the person, their organisation and their roles. So the
 * console never decides who someone is from a token it parsed itself.
 *
 * The same question is asked on every console request (EnsureSignariSession).
 * The engine reads the session, the person, the client's designation and the
 * roles on each one (ADR-007, ADR-012), so a session revoked in Signari, a
 * person deactivated or a role taken away ends console access on the next
 * request, with nothing cached here to outlive it.
 *
 * Tokens are kept in the operator's session, encrypted under APP_KEY, and never
 * shown.
 */
class SignariSignIn
{
    public const SESSION = 'signari.sign_in';

    /** The engine's latest answer to GET /admin/me for this operator, kept by EnsureSignariSession. */
    public const ME = 'signari.me';

    private const PENDING = 'signari.sign_in_pending';

    /**
     * Whether the signed-in operator may use a screen that needs $scope: the
     * roles the engine named on this request, for an operator signed in
     * through Signari; everything, for a break-glass account or a console
     * with no Signari sign-in, whose token decides instead.
     *
     * The console reads its screens from the database views under its own
     * role, not through the Admin API, so without this a person with any role
     * at all would read every screen; the engine still refuses each write the
     * role does not allow.
     */
    public static function may(string $scope): bool
    {
        $user = auth()->user();
        if (! self::configured() || $user === null || $user->break_glass) {
            return true;
        }
        $me = session(self::ME);

        return is_array($me) && in_array($scope, (array) ($me['scopes'] ?? []), true);
    }

    /**
     * Whether $scope is narrowed to some groups' members for this operator (a
     * user manager delegated over groups). The console's people screen reads
     * every person of the organisation, so it is not offered to one: they
     * administer their members through the Admin API, which holds them to it.
     */
    public static function delegated(string $scope): bool
    {
        $me = session(self::ME);

        return is_array($me) && ! empty($me['delegated'][$scope] ?? null);
    }

    /** Refreshed when this close to expiry, so a request does not carry a token that dies under it. */
    private const LEEWAY = 30;

    public static function configured(): bool
    {
        return filled(config('services.signari.issuer')) && filled(config('services.signari.client_id'));
    }

    public function issuer(): string
    {
        return rtrim((string) config('services.signari.issuer'), '/');
    }

    /** The Admin API's audience, as the engine names it (tokens.AdminAudience). */
    public function adminAudience(): string
    {
        return $this->issuer().'/admin';
    }

    public function redirectUri(): string
    {
        return (string) (config('services.signari.redirect') ?: url('/signari/callback'));
    }

    /**
     * Starts a sign-in: the URL to send the browser to. The state and the PKCE
     * verifier are kept in the session for the callback to check.
     */
    public function begin(): string
    {
        $verifier = Str::random(64);
        $state = Str::random(40);
        session()->put(self::PENDING, ['state' => $state, 'verifier' => $verifier]);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return $this->endpoint('authorization_endpoint').'?'.http_build_query([
            'response_type' => 'code',
            'client_id' => (string) config('services.signari.client_id'),
            'redirect_uri' => $this->redirectUri(),
            'scope' => 'openid',
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'acr_values' => '2',
            'resource' => $this->adminAudience(),
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Finishes it: the state checked, the code exchanged, and the person the
     * engine says the token is for. Refused for anything but a person.
     *
     * @return array<string, mixed> the engine's GET /admin/me
     */
    public function complete(string $state, string $code): array
    {
        $pending = session()->pull(self::PENDING);
        if (! is_array($pending) || ! is_string($pending['state'] ?? null)
            || ! hash_equals($pending['state'], $state)) {
            throw new SignInRefused(__('That sign-in was not started here, or was already used. Start again.'));
        }

        $tokens = $this->token([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'code_verifier' => $pending['verifier'],
        ]);
        $me = $this->me((string) $tokens['access_token']);
        if ($me === null || ($me['kind'] ?? null) !== 'person' || ! is_string($me['user']['id'] ?? null)) {
            throw new SignInRefused(__('Signari did not sign a person in to administer with.'));
        }
        if (empty($me['scopes'])) {
            throw new SignInRefused(__('You hold no administrative role in Signari.'));
        }
        $this->keep($tokens);
        session()->put(self::ME, $me);

        return $me;
    }

    /**
     * Who the signed-in operator is now, as the engine answers on this
     * request; null when it answers for nobody, which ends their console
     * session.
     *
     * @return array<string, mixed>|null
     */
    public function current(): ?array
    {
        $token = $this->accessToken();

        return $token === null ? null : $this->me($token);
    }

    /**
     * The operator's access token, refreshed when it is about to expire, or
     * null when there is none and no refresh gives one.
     */
    public function accessToken(): ?string
    {
        $kept = session(self::SESSION);
        if (! is_array($kept)) {
            return null;
        }
        if (($kept['expires_at'] ?? 0) > time() + self::LEEWAY) {
            return decrypt($kept['access_token']);
        }
        if (empty($kept['refresh_token'])) {
            session()->forget(self::SESSION);

            return null;
        }
        try {
            $tokens = $this->token([
                'grant_type' => 'refresh_token',
                'refresh_token' => decrypt($kept['refresh_token']),
            ]);
        } catch (SignInRefused) {
            session()->forget(self::SESSION);

            return null;
        }
        $this->keep($tokens);

        return (string) $tokens['access_token'];
    }

    /** Ends the console's hold on the sign-in: the refresh token revoked, the tokens forgotten. */
    public function forget(): void
    {
        session()->forget(self::ME);
        $kept = session()->pull(self::SESSION);
        if (! is_array($kept) || empty($kept['refresh_token'])) {
            return;
        }
        try {
            Http::timeout(5)->asForm()
                ->withBasicAuth((string) config('services.signari.client_id'), (string) config('services.signari.client_secret'))
                ->post($this->endpoint('revocation_endpoint'), [
                    'token' => decrypt($kept['refresh_token']),
                    'token_type_hint' => 'refresh_token',
                ]);
        } catch (ConnectionException|RuntimeException $e) {
            // The session's end in Signari still ends the grant; this only
            // saves it waiting for that.
            Log::warning('revoking the console sign-in\'s refresh token', ['error' => $e->getMessage()]);
        }
    }

    /**
     * GET /admin/me with $accessToken: the engine's answer, or null when it
     * refuses the token (401, or 403 for a session without a second factor).
     *
     * @return array<string, mixed>|null
     */
    public function me(string $accessToken): ?array
    {
        try {
            $response = Http::withToken($accessToken)->timeout(5)->acceptJson()
                ->get(EngineAdminApi::baseUrl().'/admin/me');
        } catch (ConnectionException $e) {
            throw new RuntimeException('The engine Admin API is unreachable.', previous: $e);
        }
        if ($response->status() === 401 || $response->status() === 403) {
            return null;
        }
        if (! $response->ok()) {
            throw new RuntimeException('The engine Admin API answered '.$response->status().'.');
        }

        return (array) $response->json();
    }

    /** @param array<string, mixed> $form */
    private function token(array $form): array
    {
        try {
            $response = Http::timeout(5)->asForm()->acceptJson()
                ->withBasicAuth((string) config('services.signari.client_id'), (string) config('services.signari.client_secret'))
                ->post($this->endpoint('token_endpoint'), $form);
        } catch (ConnectionException $e) {
            throw new RuntimeException('Signari is unreachable.', previous: $e);
        }
        if (! $response->ok() || ! is_string($response->json('access_token'))) {
            throw new SignInRefused(__('Signari refused the sign-in (:error).',
                ['error' => (string) $response->json('error', $response->status())]));
        }

        return (array) $response->json();
    }

    /** @param array<string, mixed> $tokens */
    private function keep(array $tokens): void
    {
        session()->put(self::SESSION, [
            'access_token' => encrypt((string) $tokens['access_token']),
            'refresh_token' => isset($tokens['refresh_token']) ? encrypt((string) $tokens['refresh_token']) : null,
            'expires_at' => time() + (int) ($tokens['expires_in'] ?? 60),
        ]);
    }

    /** One of the issuer's endpoints, from its discovery document. */
    private function endpoint(string $name): string
    {
        try {
            $response = Http::timeout(5)->acceptJson()->get($this->issuer().'/.well-known/openid-configuration');
        } catch (ConnectionException $e) {
            throw new RuntimeException('Signari is unreachable.', previous: $e);
        }
        if (! $response->ok() || rtrim((string) $response->json('issuer'), '/') !== $this->issuer()
            || ! is_string($response->json($name))) {
            throw new RuntimeException('Signari\'s discovery document does not name its '.$name.'.');
        }

        return (string) $response->json($name);
    }
}
