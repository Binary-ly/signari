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
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $token,
        private readonly int $timeoutSeconds = 5,
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
        return new self(
            rtrim((string) env('SIGNARI_ADMIN_URL', 'http://127.0.0.1:8090'), '/'),
            (string) env('SIGNARI_ADMIN_TOKEN', ''),
        );
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
        return $this->patch("/admin/clients/{$clientId}", ['enabled' => $enabled]);
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

        return (string) $this->request('post', '/admin/users', $body)['id'];
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
        return $this->request('patch', "/admin/users/{$userId}", ['active' => $active]);
    }

    /** Set a user's password. Also ends every session, for the same reason. */
    public function setUserPassword(string $userId, string $password): array
    {
        return $this->request('patch', "/admin/users/{$userId}", ['password' => $password]);
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
        ], fn ($v) => $v !== null && $v !== ''));
    }

    /**
     * Rotate a client secret. The previous one stops working IMMEDIATELY -- there
     * is no overlap window, because rotation is what you do when a secret has
     * leaked.
     */
    public function rotateClientSecret(string $clientId): array
    {
        return $this->request('post', "/admin/clients/{$clientId}/rotate-secret");
    }

    /** The engine's current config version, for showing propagation state. */
    public function configVersion(): int
    {
        return (int) $this->request('get', '/admin/config-version')['config_version'];
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

    private function request(string $method, string $path, array $body = []): array
    {
        try {
            $response = Http::withToken($this->token)
                ->timeout($this->timeoutSeconds)
                // No retries on a write. A PATCH that timed out may well have
                // committed, and retrying it blindly would be a second mutation
                // whose only visible effect is another config_version bump.
                ->acceptJson()
                ->{$method}($this->baseUrl.$path, $body);
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
