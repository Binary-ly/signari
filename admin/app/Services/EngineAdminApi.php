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

    /** The engine's current config version, for showing propagation state. */
    public function configVersion(): int
    {
        return (int) $this->request('get', '/admin/config-version')['config_version'];
    }

    private function patch(string $path, array $body): int
    {
        return (int) $this->request('patch', $path, $body)['config_version'];
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
            throw new RuntimeException('The engine rejected the admin token.');
        }
        if ($response->status() === 404) {
            throw new RuntimeException('The engine does not know that record.');
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
