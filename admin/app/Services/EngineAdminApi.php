<?php

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Client for the engine's Admin API -- the only way this application can change
 * anything in schema `core` (ADR-004).
 *
 * Every method returns the engine's new `config_version`. That is not decoration:
 * it is how the console can tell an operator whether a change has actually
 * reached the running nodes, rather than just landing in the database. A UI that
 * says "saved" the instant a write commits is lying about a distributed system.
 */
class EngineAdminApi
{
    /** The version the page making these writes was rendered from; see asOf. */
    private ?int $readAt = null;

    public function __construct(
        private readonly string $baseUrl,
        private readonly string $token,
        private readonly int $timeoutSeconds = 5,
        // The signed-in console user, sent as Signari-Operator so the engine's
        // audit record names who acted and not only the console's token: two
        // people on one token were one actor in the trail. An opaque reference,
        // never an address, because the trail is append-only.
        private readonly ?string $operator = null,
    ) {
        if ($this->token === '') {
            throw new RuntimeException(
                'SIGNARI_ADMIN_TOKEN is not set. The admin console cannot write without it, '.
                'and it has no database fallback by design (ADR-004).'
            );
        }
    }

    public static function fromConfig(): self
    {
        $user = auth()->id();

        return new self(
            rtrim((string) env('SIGNARI_ADMIN_URL', 'http://127.0.0.1:8090'), '/'),
            (string) env('SIGNARI_ADMIN_TOKEN', ''),
            operator: $user === null ? null : 'console-user:'.$user,
        );
    }

    /**
     * Writes held to the configuration version a page was rendered from (the
     * `CarriesConfigVersion` page's), sent as If-Match. Every write needs one:
     * without it there is nothing to say what the operator saw, and a write
     * conditional on a version read just before it would let a stale form win.
     */
    public function asOf(?int $renderedVersion): static
    {
        $held = clone $this;
        $held->readAt = $renderedVersion;

        return $held;
    }

    /**
     * Enable or disable a client.
     *
     * A disabled client is rejected on the very NEXT request, not at the next
     * config refresh -- the engine reads `enabled` from the database on the
     * request path. So this takes effect immediately regardless of the version.
     */
    public function setClientEnabled(string $clientId, bool $enabled): int
    {
        // Conditional. Two administrators on the same client is the exact
        // scenario the engine's precondition was built for, and this console
        // was not using it -- see conditionalPatch.
        return $this->conditionalPatch("/admin/clients/{$clientId}", ['enabled' => $enabled]);
    }

    /**
     * Create a user.
     *
     * Returns the new user's id. The PASSWORD IS OPTIONAL and omitting it is the
     * better default for onboarding: a user created without one cannot sign in
     * with a password and must use recovery, so nobody has to invent a
     * credential on somebody else's behalf and then transmit it to them.
     */
    public function createUser(string $orgId, ?string $email, ?string $username, ?string $password = null): string
    {
        $body = array_filter([
            'org_id' => $orgId,
            'email' => $email,
            'username' => $username,
            'password' => $password,
        ], fn ($v) => filled($v));

        return (string) $this->request('post', '/admin/users', $body, $this->readAt())['id'];
    }

    /**
     * Activate or deactivate a user.
     *
     * Deactivating ENDS EVERY SESSION -- the engine does that, in the same
     * transaction, through the single termination path. The count comes back so
     * the console can say how many were ended rather than implying none were.
     */
    public function setUserActive(string $userId, bool $active): array
    {
        // Conditional, like every other mutation this console makes. Two
        // administrators deciding opposite things about the same person is
        // exactly the case worth refusing.
        return $this->request('patch', "/admin/users/{$userId}",
            ['active' => $active], $this->readAt());
    }

    /**
     * Set a user's password. Also ends every session, for the same reason.
     *
     * Conditional too. A password set from a stale page could otherwise undo a
     * deactivation that landed a moment earlier -- reactivating an account
     * somebody had just closed, with a credential the operator chose.
     */
    public function setUserPassword(string $userId, string $password): array
    {
        return $this->request('patch', "/admin/users/{$userId}",
            ['password' => $password], $this->readAt());
    }

    /**
     * A person's sign-in methods as the engine lists them: what each IS, never
     * what it holds. `factors` carries a `type`, an `id` for the kinds a person
     * may hold several of, and whether each is confirmed or disabled;
     * `recovery_codes_unused` counts the codes without listing them.
     */
    public function userFactors(string $userId): array
    {
        return $this->request('get', "/admin/users/{$userId}/factors");
    }

    /**
     * Remove one of a person's sign-in methods, for somebody whose phone or key
     * is lost. The engine ends every session they hold and tells them by email
     * and a verified number. A passkey is named by its id; `recovery` with no
     * id removes the whole set.
     *
     * Conditional, like every other mutation here.
     */
    public function removeUserFactor(string $userId, string $kind, ?string $factorId = null): array
    {
        $path = "/admin/users/{$userId}/factors/".rawurlencode($kind);
        if ($factorId !== null && $factorId !== '') {
            $path .= '/'.rawurlencode($factorId);
        }

        return $this->request('delete', $path, [], $this->readAt());
    }

    /**
     * Email a person a single-use link to register a passkey, for a new starter
     * with no password or somebody whose only way in is lost. The answer names
     * the link and when it ends, never its token: the engine mints that as it
     * sends the email, so whoever issues a link cannot use it. 0 is a day.
     */
    public function sendPasskeyLink(string $userId, int $ttlSeconds = 0): array
    {
        return $this->request('post', "/admin/users/{$userId}/passkey-link",
            ['ttl_seconds' => $ttlSeconds], $this->readAt());
    }

    /**
     * Create a client. Returns the engine's response, including `client_secret`
     * for a confidential client.
     *
     * THE SECRET IS IN THIS RESPONSE AND NOWHERE ELSE. Only a hash is stored, so
     * the caller must surface it now or the operator has to rotate.
     */
    public function createClient(string $orgId, string $clientId, string $displayName,
        array $redirectUris, bool $public = false, ?string $importSecret = null): array
    {
        return $this->request('post', '/admin/clients', array_filter([
            'client_id' => $clientId,
            'org_id' => $orgId,
            'display_name' => $displayName,
            'redirect_uris' => $redirectUris,
            'public' => $public,
            'secret' => $importSecret,
        ], fn ($v) => $v !== null && $v !== ''), $this->readAt());
    }

    /**
     * Rotate a client secret. The previous one stops working IMMEDIATELY -- there
     * is no overlap window, because rotation is what you do when a secret has
     * leaked.
     */
    public function rotateClientSecret(string $clientId): array
    {
        return $this->request('post', "/admin/clients/{$clientId}/rotate-secret", [], $this->readAt());
    }

    /** The engine's current config version, for showing propagation state. */
    public function configVersion(): int
    {
        return (int) $this->request('get', '/admin/config-version')['config_version'];
    }

    /**
     * A conditional write, refused if the configuration moved underneath it.
     *
     * # The bug this closes, which was live in this console
     *
     * The engine has accepted `If-Match` on every mutation since the admin API
     * existed, and this application sent it nowhere. So the exact scenario the
     * precondition was built for was reachable here: two administrators open the
     * same client, the first disables it, the second saves an unrelated change
     * from a page rendered before that, and the client is enabled again. Nobody
     * is told, and the audit trail records two successful updates because both
     * were.
     *
     * Building the guarantee into the engine and not using it from the one
     * application that ships with it is the "a control nobody uses" shape this
     * project keeps finding elsewhere.
     *
     * # Why the version comes from the page
     *
     * It is the version the page was rendered from (asOf), not one read just
     * before the write. Read just before, it caught only two administrators
     * saving in the same moment: a form opened before somebody else's change
     * still read the new version and wrote over that change, which is the case
     * the precondition exists for. The version is global, so any configuration
     * change since the page was rendered refuses the write, the operator's
     * reload included; refusing too much is the side to err on.
     *
     * What it does and does not catch is stated rather than implied, because a
     * precondition that people believe is stronger than it is would be worse
     * than none. See PRECONDITION_SCOPE below.
     */
    public function conditionalPatch(string $path, array $body): int
    {
        return (int) $this->request('patch', $path, $body, $this->readAt())['config_version'];
    }

    /**
     * What the console's preconditions do and do not catch.
     *
     * Recorded as a constant so it appears in the code an operator's engineer
     * reads, not only in a document they may not have.
     */
    public const PRECONDITION_SCOPE =
        'Each console write sends, as If-Match, the configuration version its page '.
        'was rendered from, read before the rows it shows. A change anywhere in the '.
        'configuration after that, including one made while a form was open, refuses '.
        'the write and nothing is written. It does NOT say which change moved the '.
        'version: the version is one counter for the whole instance.';

    /**
     * The version this client's writes are held to, or a refusal when none was
     * carried: a write with nothing to say what the operator saw is not made.
     */
    private function readAt(): int
    {
        if ($this->readAt === null) {
            throw new RuntimeException(
                'This page did not carry the configuration version it was shown at, '.
                'so the change cannot be held to what you saw. Nothing was written. '.
                'Reload and try again.'
            );
        }

        return $this->readAt;
    }

    private function patch(string $path, array $body): int
    {
        return (int) $this->request('patch', $path, $body)['config_version'];
    }

    /** Accepted so a create can be distinguished from an update by status. */
    private function acceptable(int $status): bool
    {
        return $status === 200 || $status === 201;
    }

    private function request(string $method, string $path, array $body = [], ?int $ifMatch = null): array
    {
        try {
            $request = Http::withToken($this->token)
                ->timeout($this->timeoutSeconds)
                // No retries on a write. A PATCH that timed out may well have
                // committed, and retrying it blindly would be a second mutation
                // whose only visible effect is another config_version bump.
                ->acceptJson();

            if ($this->operator !== null) {
                $request = $request->withHeaders(['Signari-Operator' => $this->operator]);
            }

            if ($ifMatch !== null) {
                // Quoted, because RFC 7232 does not permit a bare entity-tag and
                // the engine refuses an unquoted one with a 400 rather than
                // ignoring it -- deliberately, since ignoring it would perform an
                // unconditional write for a caller who asked for a conditional
                // one.
                $request = $request->withHeaders(['If-Match' => '"'.$ifMatch.'"']);
            }

            $response = $request->{$method}($this->baseUrl.$path, $body);
        } catch (ConnectionException $e) {
            throw new RuntimeException(
                'The engine Admin API is unreachable. The console is read-only until it returns.',
                previous: $e
            );
        }

        if ($response->status() === 401) {
            throw new RuntimeException(
                'The engine rejected the admin token. It may have been revoked or '.
                'expired -- run `signari admin-token list` to check.'
            );
        }
        if ($response->status() === 403) {
            // Authenticated, but this token may not do that. The engine names the
            // missing scope or the organisation boundary on purpose, so passing
            // its detail through is the difference between a one-line fix and an
            // afternoon of guessing.
            throw new RuntimeException(
                (string) $response->json('detail', 'This admin token is not permitted to do that.')
            );
        }
        if ($response->status() === 404) {
            throw new RuntimeException('The engine does not know that record.');
        }
        if ($response->status() === 409) {
            // Surfaced as its own message: "already exists" is something the
            // operator can fix, unlike a generic failure.
            throw new RuntimeException(
                (string) $response->json('detail', 'That record already exists.')
            );
        }
        if ($response->status() === 412) {
            // The precondition did its job: somebody else changed the
            // configuration between this page being prepared and this write.
            //
            // Told plainly, and told that NOTHING was written. An operator who
            // does not know a refused write left the system untouched will
            // reasonably assume a partial change and go looking for it. The
            // engine names both versions, which is what makes "somebody else
            // saved" a fact rather than a guess.
            throw new RuntimeException(sprintf(
                'Somebody else changed the configuration while you were working '.
                '(it moved from version %s to %s). Nothing was written. Reload '.
                'and try again.',
                (string) $response->json('expected_version', '?'),
                (string) $response->json('current_version', '?'),
            ));
        }
        if ($response->status() === 400) {
            throw new RuntimeException(
                (string) $response->json('detail', $response->json('error', 'The engine rejected that.'))
            );
        }
        if ($response->failed()) {
            throw new RuntimeException(sprintf(
                'Engine Admin API returned %d: %s',
                $response->status(),
                (string) $response->json('error', 'unknown_error')
            ));
        }

        return (array) $response->json();
    }
}
